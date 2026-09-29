import sys
import tempfile
import threading
import unittest
from datetime import timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app import ApiError, BLOCK_REASONS, CredentialService, DelegationService, FreezeService, Store, iso, now


class DelegationTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.tmp.name) / "test.db")
        self.service = CredentialService(self.store)
        self.delegations = DelegationService(self.store)
        self.freezes = FreezeService(self.store)
        self.service.rotate_key("issuer-a", "issuer", "issuer-a")
        template = self.service.create_template(
            "issuer-a", "issuer", "degree", "学位凭证",
            [{"name": "name", "required": True}, {"name": "degree", "required": True}, {"name": "gpa", "required": False}],
            365,
        )
        self.credential = self.service.issue(
            "issuer-a", "issuer", template["id"], "alice",
            {"name": "Alice", "degree": "BSc", "gpa": "3.8"}, "issue-1",
        )
        self.template_id = template["id"]

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def _register(self, agent="agent-1", fields=("name", "degree"), days=7):
        return self.delegations.register(
            "alice", "holder", self.credential["id"], agent, list(fields),
            iso(now() + timedelta(days=days)),
        )

    def test_register_and_present_with_visibility_limit(self):
        delegation = self._register()
        self.assertEqual("active", delegation["status"])
        proof = self.delegations.present("agent-1", "agent", delegation["id"], "idem-1")
        self.assertEqual({"name", "degree"}, set(proof["payload"]["claims"]))
        self.assertNotIn("gpa", proof["token"])
        self.assertEqual("alice", proof["payload"]["holder_id"])
        self.assertEqual("agent-1", proof["payload"]["presented_by"])
        self.assertEqual(1, proof["payload"]["key_version"])
        verified = self.service.verify(proof["token"])
        self.assertTrue(verified["valid"])

    def test_only_holder_can_register_and_only_named_agent_can_present(self):
        delegation = self._register()
        with self.assertRaises(ApiError) as ctx:
            self.delegations.register("mallory", "holder", self.credential["id"], "agent-9", ["name"], iso(now() + timedelta(days=1)))
        self.assertEqual(403, ctx.exception.status)
        with self.assertRaises(ApiError) as ctx:
            self.delegations.present("agent-2", "agent", delegation["id"], "x")
        self.assertEqual("delegation_mismatch", ctx.exception.code)
        with self.assertRaises(ApiError):
            self.delegations.present("agent-1", "holder", delegation["id"], "x")

    def test_visibility_fields_validated(self):
        with self.assertRaises(ApiError) as ctx:
            self._register(fields=("name", "gpa2"))
        self.assertEqual(400, ctx.exception.status)
        delegation = self._register(fields=("name",))
        with self.assertRaises(ApiError) as ctx:
            self.delegations.present("agent-1", "agent", delegation["id"], "x", ["name", "degree"])
        self.assertEqual(400, ctx.exception.status)

    def test_same_agent_keeps_single_open_delegation(self):
        first = self._register(fields=("name",))
        second = self._register(fields=("name", "degree"))
        self.assertNotEqual(first["id"], second["id"])
        self.assertEqual("superseded", self.store.get_delegation(first["id"])["status"])
        self.assertEqual("active", self.store.get_delegation(second["id"])["status"])
        with self.assertRaises(ApiError) as ctx:
            self.delegations.present("agent-1", "agent", first["id"], "x")
        self.assertEqual("delegation_superseded", ctx.exception.code)
        # Different agents can each hold an open delegation.
        other = self._register(agent="agent-2")
        self.assertEqual("active", other["status"])

    def test_expiry_pins_to_credential_and_delegation_expiry_refuses(self):
        with self.assertRaises(ApiError):
            self.delegations.register(
                "alice", "holder", self.credential["id"], "agent-1", ["name"],
                iso(now() + timedelta(days=400)),
            )
        delegation = self._register(days=2)
        future = iso(now() + timedelta(days=3))
        with self.assertRaises(ApiError) as ctx:
            self.delegations.present("agent-1", "agent", delegation["id"], "x", at=future)
        self.assertEqual("delegation_expired", ctx.exception.code)

    def test_distinct_refusal_reasons(self):
        credential2 = self.service.issue(
            "issuer-a", "issuer", self.template_id, "bob",
            {"name": "Bob", "degree": "MA"}, "issue-2",
        )
        frozen_del = self._register()
        revoked_del = self.delegations.register(
            "alice", "holder", self.credential["id"], "agent-r",
            ["name"], iso(now() + timedelta(days=1)),
        )
        bob_del = self.delegations.register(
            "bob", "holder", credential2["id"], "agent-b",
            ["name"], iso(now() + timedelta(days=1)),
        )
        # Issuer freeze
        self.freezes.freeze("issuer-a", "issuer", "issuer-a")
        with self.assertRaises(ApiError) as ctx:
            self.delegations.present("agent-1", "agent", frozen_del["id"], "freeze-x")
        self.assertEqual("issuer_frozen", ctx.exception.code)
        # Credential revoked -> its own reason after thaw
        self.service.revoke("issuer-a", "issuer", self.credential["id"], "材料造假")
        self.freezes.unfreeze("issuer-a", "issuer", "issuer-a")
        with self.assertRaises(ApiError) as ctx:
            self.delegations.present("agent-r", "agent", revoked_del["id"], "revoke-x")
        self.assertEqual("credential_revoked", ctx.exception.code)
        # Holder-revoked delegation on a still-valid credential -> delegation reason
        self.delegations.revoke("bob", "holder", bob_del["id"], "不再委托")
        with self.assertRaises(ApiError) as ctx:
            self.delegations.present("agent-b", "agent", bob_del["id"], "del-revoked")
        self.assertEqual("delegation_revoked", ctx.exception.code)

    def test_repeated_request_reuses_first_token(self):
        delegation = self._register()
        first = self.delegations.present("agent-1", "agent", delegation["id"], "same-key", ["name"])
        second = self.delegations.present("agent-1", "agent", delegation["id"], "same-key", ["name", "degree"])
        self.assertTrue(second["idempotent_replay"])
        self.assertEqual(first["token"], second["token"])
        self.assertEqual(["name"], second["disclosed_fields"])
        presentations = self.store.conn.execute(
            "SELECT COUNT(*) AS n FROM delegation_presentations WHERE delegation_id=?", (delegation["id"],)
        ).fetchone()["n"]
        self.assertEqual(1, presentations)

    def test_concurrent_submission_succeeds_once(self):
        delegation = self._register()
        results = []

        def submit():
            try:
                results.append(self.delegations.present("agent-1", "agent", delegation["id"], "race-key", ["name"]))
            except ApiError as exc:
                results.append(exc)

        threads = [threading.Thread(target=submit) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        tokens = {r["token"] if isinstance(r, dict) else None for r in results}
        self.assertEqual(1, len(tokens))
        self.assertNotIn(None, tokens)

    def test_key_rotation_old_delegation_old_version_new_delegation_new_version(self):
        before = self._register(agent="agent-old")
        proof_before = self.delegations.present("agent-old", "agent", before["id"], "p1")
        self.assertEqual(1, proof_before["payload"]["key_version"])
        self.service.rotate_key("issuer-a", "issuer", "issuer-a")
        # Old delegation still verifies against the retired version.
        self.assertTrue(self.service.verify(proof_before["token"])["key_retired"])
        after = self._register(agent="agent-new")
        self.assertEqual(2, after["key_version"])
        proof_after = self.delegations.present("agent-new", "agent", after["id"], "p2")
        self.assertEqual(2, proof_after["payload"]["key_version"])
        self.assertFalse(self.service.verify(proof_after["token"])["key_retired"])

    def test_freeze_keeps_pending_items_blocks_presentation_unfreeze_restores(self):
        delegation = self._register()
        token = self.delegations.present("agent-1", "agent", delegation["id"], "before")["token"]
        # A dispute stays pending through the freeze.
        self.service.revoke("issuer-a", "issuer", self.credential["id"], "待查")
        dispute = self.service.dispute("alice", "holder", self.credential["id"], "依据错误")
        self.freezes.freeze("issuer-a", "issuer", "issuer-a")
        self.assertEqual("open", self.store.conn.execute("SELECT status FROM disputes WHERE id=?", (dispute["id"],)).fetchone()["status"])
        # Both delegated and direct presentation are disabled.
        with self.assertRaises(ApiError) as ctx:
            self.delegations.present("agent-1", "agent", delegation["id"], "during")
        self.assertEqual("issuer_frozen", ctx.exception.code)
        with self.assertRaises(ApiError) as ctx:
            self.service.present("alice", "holder", self.credential["id"], ["name"])
        self.assertEqual("issuer_frozen", ctx.exception.code)
        self.assertFalse(self.service.verify(token)["valid"])
        # Unfreeze restores the still-valid credential via the upheld-denied dispute resolution.
        self.service.resolve_dispute("regulator-1", "regulator", dispute["id"], "reject", "撤销不成立")
        result = self.freezes.unfreeze("issuer-a", "issuer", "issuer-a")
        self.assertIn(self.credential["id"], result["restored_credentials"])
        self.assertIn(delegation["id"], result["restored_delegations"])
        proof = self.delegations.present("agent-1", "agent", delegation["id"], "after")
        self.assertTrue(self.service.verify(proof["token"])["valid"])

    def test_unfreeze_does_not_restore_expired_items(self):
        keep = self._register(agent="agent-keep", days=5)
        lapse = self._register(agent="agent-lapse", days=5)
        # Simulate time passing past one delegation's deadline while the issuer is frozen.
        self.freezes.freeze("issuer-a", "issuer", "issuer-a")
        self.store.conn.execute(
            "UPDATE delegations SET expires_at=? WHERE id=?",
            (iso(now() - timedelta(minutes=1)), lapse["id"]),
        )
        self.store.conn.commit()
        result = self.freezes.unfreeze("issuer-a", "issuer", "issuer-a")
        self.assertIn(keep["id"], result["restored_delegations"])
        self.assertNotIn(lapse["id"], result["restored_delegations"])

    def test_online_verify_rechecks_delegation_state(self):
        delegation = self._register(days=2)
        token = self.delegations.present("agent-1", "agent", delegation["id"], "p")["token"]
        self.delegations.revoke("alice", "holder", delegation["id"], "终止")
        result = self.service.verify(token)
        self.assertFalse(result["valid"])
        self.assertEqual("delegation_revoked", result["status"])
        # Offline verification cannot reach the freeze/delegation state.
        offline = self.service.verify(token, online=False)
        self.assertTrue(offline["offline"])


if __name__ == "__main__":
    unittest.main()
