import json
import sys
import tempfile
import threading
import unittest
from datetime import timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app import ApiError, CredentialService, Store, iso, now, parse_time


class DelegationTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.service = CredentialService(Store(Path(self.tmp.name) / "test.db"))
        self.service.rotate_key("issuer-a", "issuer", "issuer-a")
        self.template = self.service.create_template(
            "issuer-a", "issuer", "degree", "学位凭证",
            [{"name": "name", "required": True}, {"name": "degree", "required": True},
             {"name": "gpa", "required": False}], 365)
        self.credential = self.service.issue(
            "issuer-a", "issuer", self.template["id"], "alice",
            {"name": "Alice", "degree": "BSc", "gpa": "3.8"}, "issue-1")
        self.later = iso(now() + timedelta(days=30))

    def tearDown(self):
        self.service.store.close()
        self.tmp.cleanup()

    def _register(self, agent="agent-bob", fields=None, expires_at=None):
        return self.service.register_delegation(
            "alice", "holder", self.credential["id"], agent,
            fields or ["name", "degree"], expires_at or self.later)

    def test_only_holder_can_register_and_fields_validated(self):
        with self.assertRaises(ApiError):
            self.service.register_delegation(
                "mallory", "holder", self.credential["id"], "agent-x", ["name"], self.later)
        with self.assertRaises(ApiError):
            self.service.register_delegation(
                "alice", "holder", self.credential["id"], "agent-x", ["nope"], self.later)
        with self.assertRaises(ApiError):
            self.service.register_delegation(
                "alice", "holder", self.credential["id"], "agent-x", ["name"], iso(now() - timedelta(hours=1)))
        delegation = self._register()
        self.assertEqual("active", delegation["status"])
        self.assertEqual(1, delegation["key_version"])
        self.assertEqual(["name", "degree"], delegation["visible_fields"])

    def test_same_agent_keeps_single_open_delegation(self):
        first = self._register(agent="agent-bob", fields=["name"])
        second = self._register(agent="agent-bob", fields=["degree"])
        self.assertNotEqual(first["id"], second["id"])
        open_rows = [d for d in self.service.state()["delegations"]
                     if d["holder_id"] == "alice" and d["agent_id"] == "agent-bob" and d["status"] == "active"]
        self.assertEqual(1, len(open_rows))
        self.assertEqual(second["id"], open_rows[0]["id"])
        ended = self.service.store.delegation(first["id"])
        self.assertEqual("ended", ended["status"])
        self.assertEqual("superseded", ended["end_reason"])
        # 不同代理人可各持一份未结束委托
        other = self._register(agent="agent-carol")
        self.assertEqual("active", self.service.store.delegation(other["id"])["status"])

    def test_agent_present_is_scoped_to_visible_fields(self):
        delegation = self._register()
        proof = self.service.agent_present("agent-bob", "agent", delegation["id"], "present-1")
        self.assertFalse(proof["replayed"])
        self.assertEqual({"name", "degree"}, set(proof["payload"]["claims"]))
        self.assertNotIn("gpa", proof["token"])
        self.assertEqual("agent", proof["payload"]["presented_by"])
        result = self.service.verify(proof["token"])
        self.assertTrue(result["valid"])
        self.assertEqual("agent", result["presented_by"])
        with self.assertRaises(ApiError):  # 其他代理人不能使用
            self.service.agent_present("agent-carol", "agent", delegation["id"], "present-x")

    def test_reject_reasons_freeze_revoke_and_expiry(self):
        delegation = self._register()
        # 签发方冻结 -> 按冻结原因拒绝；待办保留
        self.service.freeze_issuer("issuer-a", "issuer", "issuer-a", "合规检查")
        with self.assertRaises(ApiError) as ctx:
            self.service.agent_present("agent-bob", "agent", delegation["id"], "p-frozen")
        self.assertEqual("issuer_frozen", ctx.exception.reason)
        self.assertEqual("active", self.service.store.delegation(delegation["id"])["status"])
        # 冻结期间持有人本人出示也停用
        with self.assertRaises(ApiError):
            self.service.present("alice", "holder", self.credential["id"], ["name"])
        self.service.unfreeze_issuer("issuer-a", "issuer", "issuer-a")
        self.assertTrue(self.service.verify(
            self.service.agent_present("agent-bob", "agent", delegation["id"], "p-ok")["token"])["valid"])
        # 凭证撤销 -> 按撤销原因拒绝
        self.service.revoke("issuer-a", "issuer", self.credential["id"], "虚假材料")
        with self.assertRaises(ApiError) as ctx:
            self.service.agent_present("agent-bob", "agent", delegation["id"], "p-revoked")
        self.assertEqual("credential_revoked", ctx.exception.reason)
        # 委托过期 -> 按委托过期原因拒绝（直接构造过期委托）
        cred2 = self.service.issue(
            "issuer-a", "issuer", self.template["id"], "dave",
            {"name": "Dave", "degree": "MA"}, "issue-2")
        expired_delegation = self.service.register_delegation(
            "dave", "holder", cred2["id"], "agent-eve", ["name"], iso(now() + timedelta(days=1)))
        self.service.conn.execute(
            "UPDATE delegations SET expires_at=? WHERE id=?",
            (iso(now() - timedelta(minutes=1)), expired_delegation["id"]))
        self.service.conn.commit()
        with self.assertRaises(ApiError) as ctx:
            self.service.agent_present("agent-eve", "agent", expired_delegation["id"], "p-expired")
        self.assertEqual("delegation_expired", ctx.exception.reason)

    def test_key_rotation_old_delegation_stays_on_old_version(self):
        old = self._register()  # 版本 1
        self.service.rotate_key("issuer-a", "issuer", "issuer-a")
        # 老委托仍按 v1 验证
        proof_old = self.service.agent_present("agent-bob", "agent", old["id"], "p-v1")
        self.assertEqual(1, proof_old["payload"]["key_version"])
        result_old = self.service.verify(proof_old["token"])
        self.assertTrue(result_old["valid"])
        self.assertTrue(result_old["key_retired"])
        # 新登记委托走新版本
        new = self._register(agent="agent-carol")
        self.assertEqual(2, new["key_version"])
        proof_new = self.service.agent_present("agent-carol", "agent", new["id"], "p-v2")
        self.assertEqual(2, proof_new["payload"]["key_version"])
        self.assertFalse(self.service.verify(proof_new["token"])["key_retired"])

    def test_repeated_request_reuses_first_token(self):
        delegation = self._register()
        first = self.service.agent_present("agent-bob", "agent", delegation["id"], "same-key")
        second = self.service.agent_present("agent-bob", "agent", delegation["id"], "same-key")
        self.assertFalse(first.get("replayed"))
        self.assertTrue(second.get("replayed"))
        self.assertEqual(first["token"], second["token"])
        rows = self.service.conn.execute(
            "SELECT COUNT(*) c FROM delegation_presentations WHERE delegation_id=? AND idempotency_key=?",
            (delegation["id"], "same-key")).fetchone()
        self.assertEqual(1, rows["c"])
        # 即使撤销后重复请求，仍沿用首次令牌（不按撤销拒绝）
        self.service.revoke("issuer-a", "issuer", self.credential["id"], "r")
        replay = self.service.agent_present("agent-bob", "agent", delegation["id"], "same-key")
        self.assertEqual(first["token"], replay["token"])
        # 对该令牌的在线验证则反映当前撤销状态
        self.assertEqual("revoked", self.service.verify(replay["token"])["status"])

    def test_concurrent_submissions_succeed_once(self):
        delegation = self._register()
        tokens: list[str] = []
        errors: list[Exception] = []

        def worker(i: int):
            try:
                proof = self.service.agent_present("agent-bob", "agent", delegation["id"], "race-key")
                tokens.append(proof["token"])
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual([], errors)
        self.assertEqual(8, len(tokens))
        self.assertEqual(1, len(set(tokens)))
        rows = self.service.conn.execute(
            "SELECT COUNT(*) c FROM delegation_presentations WHERE delegation_id=?", (delegation["id"],)).fetchone()
        self.assertEqual(1, rows["c"])

    def test_unfreeze_restores_only_currently_valid(self):
        valid = self._register(agent="agent-bob")
        # 冻结期间过期的委托：解冻时不恢复
        will_expire = self._register(agent="agent-carol")
        self.service.freeze_issuer("issuer-a", "issuer", "issuer-a", "检查")
        self.service.conn.execute(
            "UPDATE delegations SET expires_at=? WHERE id=?",
            (iso(now() - timedelta(minutes=1)), will_expire["id"]))
        self.service.conn.commit()
        result = self.service.unfreeze_issuer("issuer-a", "issuer", "issuer-a")
        self.assertIn(valid["id"], result["restored_delegations"])
        self.assertEqual(
            [{"delegation_id": will_expire["id"], "reason": "delegation_expired"}],
            result["not_restored"])
        # 解冻后有效委托恢复出示
        proof = self.service.agent_present("agent-bob", "agent", valid["id"], "p-restored")
        self.assertTrue(self.service.verify(proof["token"])["valid"])
        with self.assertRaises(ApiError) as ctx:
            self.service.agent_present("agent-carol", "agent", will_expire["id"], "p-still-expired")
        self.assertEqual("delegation_expired", ctx.exception.reason)


if __name__ == "__main__":
    unittest.main()
