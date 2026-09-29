#!/usr/bin/env python3
"""Minimal standards-library digital credential service for local evaluation."""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import sys
import threading
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

DB_PATH = Path(__file__).with_name("data.db")


def now() -> datetime:
    return datetime.now(timezone.utc)


def iso(value: datetime | None = None) -> str:
    return (value or now()).isoformat(timespec="seconds").replace("+00:00", "Z")


def parse_time(value: str | None) -> datetime:
    if not value:
        return now()
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def sign_token(conn: sqlite3.Connection, payload: dict, issuer: str, key_version: int) -> tuple[str, str]:
    """Sign a token with the pinned key version; rotation never re-signs old tokens."""
    key = conn.execute(
        "SELECT secret_hex FROM key_versions WHERE issuer=? AND version=?", (issuer, key_version)
    ).fetchone()
    if not key:
        raise ApiError(409, "无法找到签发密钥版本")
    signature = hmac.new(bytes.fromhex(key["secret_hex"]), canonical(payload), hashlib.sha256).hexdigest()
    token = base64.urlsafe_b64encode(canonical({"payload": payload, "signature": signature})).decode().rstrip("=")
    return token, signature


class ApiError(Exception):
    def __init__(self, status: int, message: str, code: str | None = None):
        super().__init__(message)
        self.status = status
        self.message = message
        self.code = code


class Store:
    def __init__(self, path: str | os.PathLike[str] = DB_PATH):
        self.path = str(path)
        self.conn = sqlite3.connect(self.path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.conn.execute("PRAGMA journal_mode=WAL")
        self._write_lock = threading.RLock()
        self.init_schema()

    @contextmanager
    def write(self):
        """Serialize writers: one shared connection must not interleave transactions across threads."""
        with self._write_lock:
            with self.conn:
                yield self.conn

    def init_schema(self) -> None:
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS key_versions (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              issuer TEXT NOT NULL,
              version INTEGER NOT NULL,
              secret_hex TEXT NOT NULL,
              status TEXT NOT NULL CHECK(status IN ('active','retired')),
              created_at TEXT NOT NULL,
              retired_at TEXT,
              UNIQUE(issuer, version)
            );
            CREATE TABLE IF NOT EXISTS templates (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              issuer TEXT NOT NULL,
              code TEXT NOT NULL,
              name TEXT NOT NULL,
              fields_json TEXT NOT NULL,
              validity_days INTEGER NOT NULL CHECK(validity_days BETWEEN 1 AND 3650),
              status TEXT NOT NULL CHECK(status IN ('active','disabled')),
              created_at TEXT NOT NULL,
              UNIQUE(issuer, code)
            );
            CREATE TABLE IF NOT EXISTS credentials (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              template_id INTEGER NOT NULL REFERENCES templates(id),
              issuer TEXT NOT NULL,
              holder_id TEXT NOT NULL,
              claims_json TEXT NOT NULL,
              issued_at TEXT NOT NULL,
              valid_until TEXT NOT NULL,
              status TEXT NOT NULL CHECK(status IN ('active','revoked','disputed')),
              key_version INTEGER NOT NULL,
              idempotency_key TEXT NOT NULL,
              revocation_reason TEXT,
              revocation_effective_at TEXT,
              UNIQUE(template_id, holder_id, idempotency_key)
            );
            CREATE UNIQUE INDEX IF NOT EXISTS one_live_credential
              ON credentials(template_id, holder_id)
              WHERE status IN ('active','disputed');
            CREATE TABLE IF NOT EXISTS disputes (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              credential_id INTEGER NOT NULL REFERENCES credentials(id),
              raised_by TEXT NOT NULL,
              reason TEXT NOT NULL,
              status TEXT NOT NULL CHECK(status IN ('open','upheld','rejected')),
              resolution TEXT,
              created_at TEXT NOT NULL,
              resolved_at TEXT
            );
            CREATE TABLE IF NOT EXISTS audit_log (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              at TEXT NOT NULL,
              actor TEXT NOT NULL,
              action TEXT NOT NULL,
              entity_type TEXT NOT NULL,
              entity_id TEXT NOT NULL,
              details_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS delegations (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              credential_id INTEGER NOT NULL REFERENCES credentials(id),
              issuer TEXT NOT NULL,
              holder_id TEXT NOT NULL,
              agent_id TEXT NOT NULL,
              visible_fields_json TEXT NOT NULL,
              expires_at TEXT NOT NULL,
              key_version INTEGER NOT NULL,
              status TEXT NOT NULL CHECK(status IN ('active','superseded','revoked')),
              created_at TEXT NOT NULL,
              revoked_reason TEXT
            );
            CREATE UNIQUE INDEX IF NOT EXISTS one_open_delegation_per_agent
              ON delegations(holder_id, agent_id)
              WHERE status='active';
            CREATE TABLE IF NOT EXISTS delegation_presentations (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              delegation_id INTEGER NOT NULL REFERENCES delegations(id),
              idempotency_key TEXT NOT NULL,
              disclosed_fields_json TEXT NOT NULL,
              token TEXT NOT NULL,
              payload_json TEXT NOT NULL,
              signature TEXT NOT NULL,
              created_at TEXT NOT NULL,
              UNIQUE(delegation_id, idempotency_key)
            );
            CREATE TABLE IF NOT EXISTS issuer_freezes (
              issuer TEXT PRIMARY KEY,
              frozen_at TEXT NOT NULL
            );
            """
        )
        self.conn.commit()

    def audit(self, actor: str, action: str, entity_type: str, entity_id: object, details: dict) -> None:
        self.conn.execute(
            "INSERT INTO audit_log(at,actor,action,entity_type,entity_id,details_json) VALUES(?,?,?,?,?,?)",
            (iso(), actor, action, entity_type, str(entity_id), json.dumps(details, ensure_ascii=False)),
        )

    # ---- delegation records -------------------------------------------------
    def get_delegation(self, delegation_id: int) -> sqlite3.Row | None:
        return self.conn.execute("SELECT * FROM delegations WHERE id=?", (delegation_id,)).fetchone()

    def get_active_delegation(self, holder_id: str, agent_id: str) -> sqlite3.Row | None:
        return self.conn.execute(
            "SELECT * FROM delegations WHERE holder_id=? AND agent_id=? AND status='active'", (holder_id, agent_id)
        ).fetchone()

    def insert_delegation(self, credential_id: int, issuer: str, holder_id: str, agent_id: str,
                          visible_fields: list[str], expires_at: str, key_version: int) -> int:
        cur = self.conn.execute(
            """INSERT INTO delegations(credential_id,issuer,holder_id,agent_id,visible_fields_json,expires_at,
                                       key_version,status,created_at)
               VALUES(?,?,?,?,?,?,?, 'active',?)""",
            (credential_id, issuer, holder_id, agent_id, json.dumps(visible_fields, ensure_ascii=False),
             expires_at, key_version, iso()),
        )
        return int(cur.lastrowid)

    def supersede_delegations(self, holder_id: str, agent_id: str) -> int:
        cur = self.conn.execute(
            "UPDATE delegations SET status='superseded' WHERE holder_id=? AND agent_id=? AND status='active'",
            (holder_id, agent_id),
        )
        return cur.rowcount

    def revoke_delegation(self, delegation_id: int, reason: str) -> None:
        self.conn.execute(
            "UPDATE delegations SET status='revoked',revoked_reason=? WHERE id=?", (reason, delegation_id)
        )

    def list_delegations(self) -> list[sqlite3.Row]:
        return list(self.conn.execute("SELECT * FROM delegations ORDER BY id DESC"))

    def restorable_delegation_ids(self, issuer: str, at: datetime) -> list[int]:
        rows = self.conn.execute(
            "SELECT id FROM delegations WHERE issuer=? AND status='active' AND expires_at>?",
            (issuer, iso(at)),
        ).fetchall()
        return [int(row["id"]) for row in rows]

    # ---- delegated presentation records -------------------------------------
    def get_presentation(self, delegation_id: int, idempotency_key: str) -> sqlite3.Row | None:
        return self.conn.execute(
            "SELECT * FROM delegation_presentations WHERE delegation_id=? AND idempotency_key=?",
            (delegation_id, idempotency_key),
        ).fetchone()

    def insert_presentation(self, delegation_id: int, idempotency_key: str, disclosed_fields: list[str],
                            token: str, payload: dict, signature: str) -> int:
        cur = self.conn.execute(
            """INSERT INTO delegation_presentations(delegation_id,idempotency_key,disclosed_fields_json,token,
                                                    payload_json,signature,created_at)
               VALUES(?,?,?,?,?,?,?)""",
            (delegation_id, idempotency_key, json.dumps(disclosed_fields, ensure_ascii=False), token,
             json.dumps(payload, ensure_ascii=False), signature, iso()),
        )
        return int(cur.lastrowid)

    # ---- issuer freeze records ----------------------------------------------
    def get_freeze(self, issuer: str) -> sqlite3.Row | None:
        return self.conn.execute("SELECT * FROM issuer_freezes WHERE issuer=?", (issuer,)).fetchone()

    def is_issuer_frozen(self, issuer: str) -> bool:
        return self.get_freeze(issuer) is not None

    def freeze_issuer(self, issuer: str) -> None:
        self.conn.execute(
            "INSERT INTO issuer_freezes(issuer,frozen_at) VALUES(?,?) ON CONFLICT(issuer) DO NOTHING",
            (issuer, iso()),
        )

    def unfreeze_issuer(self, issuer: str) -> None:
        self.conn.execute("DELETE FROM issuer_freezes WHERE issuer=?", (issuer,))

    def restorable_credential_ids(self, issuer: str, at: datetime) -> list[int]:
        rows = self.conn.execute(
            "SELECT id FROM credentials WHERE issuer=? AND status='active' AND valid_until>?",
            (issuer, iso(at)),
        ).fetchall()
        return [int(row["id"]) for row in rows]

    def close(self) -> None:
        self.conn.close()


class DelegationPolicy:
    """Pure state decisions: takes rows/dicts, never touches the database."""

    @staticmethod
    def credential_block(credential: sqlite3.Row | dict, at: datetime) -> str | None:
        """Return the credential-side refusal code, or None when still usable."""
        if at >= parse_time(credential["valid_until"]):
            return "credential_expired"
        if credential["status"] == "disputed":
            return "credential_disputed"
        if credential["status"] == "revoked":
            if at >= parse_time(credential["revocation_effective_at"]):
                return "credential_revoked"
        return None

    @staticmethod
    def delegation_block(delegation: sqlite3.Row | dict, credential: sqlite3.Row | dict,
                         agent_id: str, at: datetime) -> str | None:
        """Return the delegation-side refusal code, or None when the delegation is usable."""
        if delegation["credential_id"] != credential["id"]:
            return "delegation_mismatch"
        if delegation["agent_id"] != agent_id:
            return "delegation_mismatch"
        if delegation["status"] == "revoked":
            return "delegation_revoked"
        if delegation["status"] == "superseded":
            return "delegation_superseded"
        if at >= parse_time(delegation["expires_at"]):
            return "delegation_expired"
        return None

    @classmethod
    def presentation_block(cls, *, issuer_frozen: bool, credential, delegation,
                           agent_id: str, at: datetime) -> str | None:
        """Ordered gate: issuer freeze -> credential state -> delegation state, each with its own code."""
        if issuer_frozen:
            return "issuer_frozen"
        blocked = cls.credential_block(credential, at)
        if blocked:
            return blocked
        return cls.delegation_block(delegation, credential, agent_id, at)


BLOCK_REASONS = {
    "issuer_frozen": "签发方已冻结本机构委托，出示停用",
    "credential_expired": "凭证已过期",
    "credential_disputed": "撤销决定正在争议复核",
    "credential_revoked": "凭证已撤销",
    "delegation_expired": "委托已过期",
    "delegation_revoked": "委托已被持有人撤销",
    "delegation_superseded": "委托已被同一代理人的新委托取代",
    "delegation_mismatch": "委托与代理人或凭证不匹配",
}


def require_actor(actor: str | None, role: str | None, expected: str) -> str:
    if not actor:
        raise ApiError(401, "缺少身份")
    if role != expected:
        raise ApiError(403, f"需要角色 {expected}")
    return actor


class CredentialService:
    """Credential issuance and verification with small, explicit trust boundaries."""

    def __init__(self, store: Store):
        self.store = store
        self.conn = store.conn

    @staticmethod
    def _required_actor(actor: str | None, role: str | None, expected: str) -> str:
        if not actor:
            raise ApiError(401, "缺少身份")
        if role != expected:
            raise ApiError(403, f"需要角色 {expected}")
        return actor

    def _row(self, table: str, identity: int) -> sqlite3.Row:
        row = self.conn.execute(f"SELECT * FROM {table} WHERE id=?", (identity,)).fetchone()
        if not row:
            raise ApiError(404, "对象不存在")
        return row

    def _active_key(self, issuer: str) -> sqlite3.Row:
        row = self.conn.execute(
            "SELECT * FROM key_versions WHERE issuer=? AND status='active' ORDER BY version DESC LIMIT 1", (issuer,)
        ).fetchone()
        if not row:
            raise ApiError(409, "签发方尚未初始化密钥")
        return row

    def rotate_key(self, actor: str | None, role: str | None, issuer: str) -> dict:
        actor = self._required_actor(actor, role, "issuer")
        if actor != issuer:
            raise ApiError(403, "只能轮换自己的密钥")
        with self.store.write():
            old = self.conn.execute("SELECT * FROM key_versions WHERE issuer=? AND status='active'", (issuer,)).fetchone()
            version = 1
            if old:
                version = int(old["version"]) + 1
                self.conn.execute("UPDATE key_versions SET status='retired', retired_at=? WHERE id=?", (iso(), old["id"]))
            secret_hex = secrets.token_hex(32)
            cur = self.conn.execute(
                "INSERT INTO key_versions(issuer,version,secret_hex,status,created_at) VALUES(?,?,?,'active',?)",
                (issuer, version, secret_hex, iso()),
            )
            self.store.audit(actor, "key.rotate", "key_version", cur.lastrowid, {"version": version, "retired_previous": bool(old)})
        return {"issuer": issuer, "version": version, "status": "active", "public_fingerprint": hashlib.sha256(secret_hex.encode()).hexdigest()[:20]}

    def create_template(self, actor: str | None, role: str | None, code: str, name: str, fields: list[dict], validity_days: int) -> dict:
        actor = self._required_actor(actor, role, "issuer")
        if not code.strip() or not name.strip():
            raise ApiError(400, "模板代号和名称不能为空")
        field_names: set[str] = set()
        normalized = []
        for field in fields:
            field_name = str(field.get("name", "")).strip()
            if not field_name or field_name in field_names:
                raise ApiError(400, "模板字段为空或重复")
            field_names.add(field_name)
            normalized.append({"name": field_name, "required": bool(field.get("required", False))})
        if not normalized:
            raise ApiError(400, "模板至少需要一个字段")
        try:
            with self.store.write():
                cur = self.conn.execute(
                    "INSERT INTO templates(issuer,code,name,fields_json,validity_days,status,created_at) VALUES(?,?,?,?,?,'active',?)",
                    (actor, code, name, json.dumps(normalized, ensure_ascii=False), int(validity_days), iso()),
                )
                self.store.audit(actor, "template.create", "template", cur.lastrowid, {"code": code, "fields": normalized})
        except sqlite3.IntegrityError as exc:
            raise ApiError(409, "同一签发方不能重复使用模板代号") from exc
        return {"id": cur.lastrowid, "issuer": actor, "code": code, "name": name, "fields": normalized, "validity_days": validity_days, "status": "active"}

    def issue(self, actor: str | None, role: str | None, template_id: int, holder_id: str, claims: dict, idempotency_key: str, valid_until: str | None = None) -> dict:
        actor = self._required_actor(actor, role, "issuer")
        if not holder_id.strip() or not idempotency_key.strip():
            raise ApiError(400, "持有人和幂等键不能为空")
        template = self._row("templates", template_id)
        if template["issuer"] != actor:
            raise ApiError(403, "不能使用其他签发方的模板")
        if template["status"] != "active":
            raise ApiError(409, "模板已停用")
        existing = self.conn.execute(
            "SELECT * FROM credentials WHERE template_id=? AND holder_id=? AND idempotency_key=?",
            (template_id, holder_id, idempotency_key),
        ).fetchone()
        if existing:
            return self._credential_dict(existing)
        fields = json.loads(template["fields_json"])
        missing = [f["name"] for f in fields if f["required"] and not str(claims.get(f["name"], "")).strip()]
        unknown = sorted(set(claims) - {f["name"] for f in fields})
        if missing or unknown:
            raise ApiError(400, f"声明不完整，缺少={missing}，未知字段={unknown}")
        live = self.conn.execute(
            "SELECT id FROM credentials WHERE template_id=? AND holder_id=? AND status IN ('active','disputed')",
            (template_id, holder_id),
        ).fetchone()
        if live:
            raise ApiError(409, "该持有人已有有效的同模板凭证；重复提交应使用相同幂等键")
        issued = now()
        expiration = parse_time(valid_until) if valid_until else issued + timedelta(days=int(template["validity_days"]))
        if expiration <= issued:
            raise ApiError(400, "有效期必须晚于签发时间")
        key = self._active_key(actor)
        try:
            with self.store.write():
                cur = self.conn.execute(
                    """INSERT INTO credentials(template_id,issuer,holder_id,claims_json,issued_at,valid_until,status,key_version,idempotency_key)
                       VALUES(?,?,?,?,?,?, 'active',?,?)""",
                    (template_id, actor, holder_id, json.dumps(claims, ensure_ascii=False), iso(issued), iso(expiration), key["version"], idempotency_key),
                )
                self.store.audit(actor, "credential.issue", "credential", cur.lastrowid, {"holder_id": holder_id, "template_id": template_id, "key_version": key["version"]})
        except sqlite3.IntegrityError as exc:
            raise ApiError(409, "并发签发冲突，请用相同幂等键重试") from exc
        return self._credential_dict(self._row("credentials", cur.lastrowid))

    def revoke(self, actor: str | None, role: str | None, credential_id: int, reason: str, effective_at: str | None = None) -> dict:
        actor = self._required_actor(actor, role, "issuer")
        credential = self._row("credentials", credential_id)
        if credential["issuer"] != actor:
            raise ApiError(403, "只能撤销本机构签发的凭证")
        if credential["status"] == "revoked":
            if credential["revocation_reason"] == reason:
                return self._credential_dict(credential)
            raise ApiError(409, "凭证已经撤销")
        effective = parse_time(effective_at) if effective_at else now()
        with self.store.write():
            self.conn.execute(
                "UPDATE credentials SET status='revoked',revocation_reason=?,revocation_effective_at=? WHERE id=?",
                (reason, iso(effective), credential_id),
            )
            self.store.audit(actor, "credential.revoke", "credential", credential_id, {"reason": reason, "effective_at": iso(effective)})
        return self._credential_dict(self._row("credentials", credential_id))

    def dispute(self, actor: str | None, role: str | None, credential_id: int, reason: str) -> dict:
        actor = self._required_actor(actor, role, "holder")
        credential = self._row("credentials", credential_id)
        if credential["holder_id"] != actor:
            raise ApiError(403, "只能对自己的凭证提出争议")
        if credential["status"] != "revoked":
            raise ApiError(409, "只有已撤销凭证可以提出争议")
        open_dispute = self.conn.execute("SELECT id FROM disputes WHERE credential_id=? AND status='open'", (credential_id,)).fetchone()
        if open_dispute:
            raise ApiError(409, "已有待处理争议")
        with self.store.write():
            cur = self.conn.execute(
                "INSERT INTO disputes(credential_id,raised_by,reason,status,created_at) VALUES(?,?,?,'open',?)",
                (credential_id, actor, reason, iso()),
            )
            self.conn.execute("UPDATE credentials SET status='disputed' WHERE id=?", (credential_id,))
            self.store.audit(actor, "dispute.open", "credential", credential_id, {"dispute_id": cur.lastrowid, "reason": reason})
        return {"id": cur.lastrowid, "credential_id": credential_id, "status": "open"}

    def resolve_dispute(self, actor: str | None, role: str | None, dispute_id: int, decision: str, resolution: str) -> dict:
        actor = self._required_actor(actor, role, "regulator")
        if decision not in {"uphold", "reject"}:
            raise ApiError(400, "决定只能是 uphold 或 reject")
        dispute = self._row("disputes", dispute_id)
        if dispute["status"] != "open":
            raise ApiError(409, "争议已经处理")
        credential = self._row("credentials", dispute["credential_id"])
        if credential["status"] != "disputed":
            raise ApiError(409, "凭证状态与争议不一致")
        new_status = "revoked" if decision == "uphold" else "active"
        dispute_status = "upheld" if decision == "uphold" else "rejected"
        with self.store.write():
            self.conn.execute("UPDATE disputes SET status=?,resolution=?,resolved_at=? WHERE id=?", (dispute_status, resolution, iso(), dispute_id))
            self.conn.execute("UPDATE credentials SET status=? WHERE id=?", (new_status, credential["id"]))
            self.store.audit(actor, "dispute.resolve", "dispute", dispute_id, {"decision": decision, "credential_status": new_status})
        return {"id": dispute_id, "status": decision, "credential_status": new_status, "resolution": resolution}

    def present(self, actor: str | None, role: str | None, credential_id: int, disclosed_fields: list[str] | None) -> dict:
        actor = self._required_actor(actor, role, "holder")
        credential = self._row("credentials", credential_id)
        if credential["holder_id"] != actor:
            raise ApiError(403, "不能出示他人的凭证")
        if self.store.is_issuer_frozen(credential["issuer"]):
            raise ApiError(409, BLOCK_REASONS["issuer_frozen"], "issuer_frozen")
        template = self._row("templates", credential["template_id"])
        allowed = [field["name"] for field in json.loads(template["fields_json"])]
        disclosed = disclosed_fields if disclosed_fields is not None else allowed
        if len(disclosed) != len(set(disclosed)) or any(name not in allowed for name in disclosed):
            raise ApiError(400, "披露字段不在模板中或重复")
        claims = json.loads(credential["claims_json"])
        visible = {name: claims[name] for name in disclosed}
        payload = {
            "credential_id": credential["id"],
            "template_id": credential["template_id"],
            "issuer": credential["issuer"],
            "holder_id": credential["holder_id"],
            "claims": visible,
            "valid_until": credential["valid_until"],
            "key_version": credential["key_version"],
        }
        token, signature = sign_token(self.conn, payload, credential["issuer"], credential["key_version"])
        with self.store.write():
            self.store.audit(actor, "credential.present", "credential", credential_id, {"disclosed_fields": disclosed})
        return {"token": token, "payload": payload, "signature": signature, "disclosed_fields": disclosed}

    def verify(self, token: str, at: str | None = None, online: bool = True) -> dict:
        if not token:
            raise ApiError(400, "缺少凭证令牌")
        try:
            padded = token + "=" * (-len(token) % 4)
            envelope = json.loads(base64.urlsafe_b64decode(padded.encode()))
            payload = envelope["payload"]
            supplied_signature = envelope["signature"]
        except (ValueError, KeyError, json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ApiError(400, "凭证令牌格式错误") from exc
        credential = self._row("credentials", int(payload.get("credential_id", 0)))
        token_key_version = int(payload.get("key_version", 0))
        key = self.conn.execute(
            "SELECT * FROM key_versions WHERE issuer=? AND version=?", (credential["issuer"], token_key_version)
        ).fetchone()
        if not key:
            raise ApiError(409, "无法找到签发密钥版本")
        expected = hmac.new(bytes.fromhex(key["secret_hex"]), canonical(payload), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, str(supplied_signature)):
            raise ApiError(400, "凭证签名无效")
        check_at = parse_time(at)
        expiration = parse_time(credential["valid_until"])
        result = {"valid": True, "status": "valid", "key_retired": key["status"] == "retired", "claims": payload.get("claims", {})}
        if check_at >= expiration:
            result.update(valid=False, status="expired", reason="凭证已过期", code="credential_expired")
        elif credential["status"] == "disputed":
            result.update(valid=False, status="disputed", reason="撤销决定正在争议复核", code="credential_disputed")
        elif credential["status"] == "revoked":
            effective = parse_time(credential["revocation_effective_at"])
            if check_at >= effective:
                result.update(valid=False, status="revoked", reason=credential["revocation_reason"], code="credential_revoked")
            else:
                result.update(status="valid_until_revocation", revocation_starts_at=credential["revocation_effective_at"])
        if online and result["valid"]:
            # Online re-check of the controlled-presentation gates; signature alone never bypasses them.
            delegation_id = payload.get("delegation_id")
            if delegation_id is not None:
                delegation = self.store.get_delegation(int(delegation_id))
                if delegation is None:
                    result.update(valid=False, status="delegation_revoked",
                                  reason="委托不存在", code="delegation_revoked")
                else:
                    block = DelegationPolicy.delegation_block(
                        delegation, credential, str(payload.get("presented_by", "")), check_at
                    )
                    if block:
                        result.update(valid=False, status=block, reason=BLOCK_REASONS[block], code=block)
            if result["valid"] and self.store.is_issuer_frozen(credential["issuer"]):
                result.update(valid=False, status="issuer_frozen",
                              reason=BLOCK_REASONS["issuer_frozen"], code="issuer_frozen")
        if not online:
            result["offline"] = True
            result["revocation_freshness"] = "needs_online_check"
            if result["valid"]:
                result["status"] = "valid_offline"
        return result

    def _credential_dict(self, row: sqlite3.Row) -> dict:
        return {
            "id": row["id"], "template_id": row["template_id"], "issuer": row["issuer"], "holder_id": row["holder_id"],
            "claims": json.loads(row["claims_json"]), "issued_at": row["issued_at"], "valid_until": row["valid_until"],
            "status": row["status"], "key_version": row["key_version"], "revocation_reason": row["revocation_reason"],
            "revocation_effective_at": row["revocation_effective_at"],
        }

    def state(self) -> dict:
        credentials = [self._credential_dict(row) for row in self.conn.execute("SELECT * FROM credentials ORDER BY id DESC")]
        templates = [dict(row) for row in self.conn.execute("SELECT id,issuer,code,name,status,validity_days FROM templates ORDER BY id DESC")]
        audits = [dict(row) for row in self.conn.execute("SELECT at,actor,action,entity_type,entity_id,details_json FROM audit_log ORDER BY id DESC LIMIT 30")]
        return {"templates": templates, "credentials": credentials, "audits": audits}

    def seed(self) -> None:
        if not self.conn.execute("SELECT id FROM key_versions LIMIT 1").fetchone():
            self.rotate_key("issuer-demo", "issuer", "issuer-demo")
        if not self.conn.execute("SELECT id FROM templates LIMIT 1").fetchone():
            self.create_template("issuer-demo", "issuer", "student-v1", "学生身份", [{"name": "name", "required": True}, {"name": "program", "required": True}, {"name": "degree", "required": False}], 365)


class DelegationService:
    """Controlled presentation on someone else's behalf.

    Request handling (Handler), state decisions (DelegationPolicy) and record
    keeping (Store) are kept as separate layers.
    """

    def __init__(self, store: Store):
        self.store = store
        self.conn = store.conn

    def _credential(self, credential_id: int) -> sqlite3.Row:
        credential = self.conn.execute("SELECT * FROM credentials WHERE id=?", (credential_id,)).fetchone()
        if not credential:
            raise ApiError(404, "凭证不存在")
        return credential

    @staticmethod
    def _delegation_dict(row: sqlite3.Row) -> dict:
        return {
            "id": row["id"], "credential_id": row["credential_id"], "issuer": row["issuer"],
            "holder_id": row["holder_id"], "agent_id": row["agent_id"],
            "visible_fields": json.loads(row["visible_fields_json"]), "expires_at": row["expires_at"],
            "key_version": row["key_version"], "status": row["status"], "created_at": row["created_at"],
            "revoked_reason": row["revoked_reason"],
        }

    def register(self, actor: str | None, role: str | None, credential_id: int, agent_id: str,
                 visible_fields: list[str], expires_at: str) -> dict:
        """Holder registers an agent. Re-registering the same agent ends the previous delegation."""
        holder = require_actor(actor, role, "holder")
        agent_id = str(agent_id or "").strip()
        if not agent_id:
            raise ApiError(400, "代理人不能为空")
        if agent_id == holder:
            raise ApiError(400, "代理人不能是持有人本人")
        credential = self._credential(credential_id)
        if credential["holder_id"] != holder:
            raise ApiError(403, "只能为自己的凭证登记代理人")
        if DelegationPolicy.credential_block(credential, now()):
            raise ApiError(409, "只能为当前有效的凭证登记委托", "credential_not_active")
        template = self.conn.execute("SELECT * FROM templates WHERE id=?", (credential["template_id"],)).fetchone()
        allowed = [field["name"] for field in json.loads(template["fields_json"])]
        fields = [str(name).strip() for name in (visible_fields or [])]
        if not fields or len(fields) != len(set(fields)) or any(name not in allowed for name in fields):
            raise ApiError(400, "可见字段为空、重复或不在模板中")
        expiry = parse_time(expires_at if expires_at else None)
        if expiry <= now():
            raise ApiError(400, "截止时间必须晚于当前时间")
        if expiry >= parse_time(credential["valid_until"]):
            raise ApiError(400, "委托截止时间不能晚于凭证有效期")
        active_key = self.conn.execute(
            "SELECT version FROM key_versions WHERE issuer=? AND status='active' ORDER BY version DESC LIMIT 1",
            (credential["issuer"],),
        ).fetchone()
        if not active_key:
            raise ApiError(409, "签发方尚未初始化密钥")
        # Pinned to the issuer's current key version at registration; later rotations never touch it.
        key_version = int(active_key["version"])
        with self.store.write():
            superseded = self.store.supersede_delegations(holder, agent_id)
            delegation_id = self.store.insert_delegation(
                credential["id"], credential["issuer"], holder, agent_id, fields, iso(expiry), key_version
            )
            self.store.audit(holder, "delegation.register", "delegation", delegation_id,
                             {"credential_id": credential["id"], "agent_id": agent_id,
                              "visible_fields": fields, "expires_at": iso(expiry),
                              "key_version": key_version, "superseded": superseded})
        return self._delegation_dict(self.store.get_delegation(delegation_id))  # type: ignore[arg-type]

    def revoke(self, actor: str | None, role: str | None, delegation_id: int, reason: str) -> dict:
        holder = require_actor(actor, role, "holder")
        delegation = self.store.get_delegation(delegation_id)
        if delegation is None:
            raise ApiError(404, "委托不存在")
        if delegation["holder_id"] != holder:
            raise ApiError(403, "只能撤销自己登记的委托")
        if delegation["status"] != "active":
            return self._delegation_dict(delegation)
        if not str(reason or "").strip():
            raise ApiError(400, "撤销原因不能为空")
        with self.store.write():
            self.store.revoke_delegation(delegation_id, reason)
            self.store.audit(holder, "delegation.revoke", "delegation", delegation_id, {"reason": reason})
        return self._delegation_dict(self.store.get_delegation(delegation_id))  # type: ignore[arg-type]

    def present(self, actor: str | None, role: str | None, delegation_id: int, idempotency_key: str,
                disclosed_fields: list[str] | None = None, at: str | None = None) -> dict:
        """Agent generates a token from a delegation; repeat/concurrent calls share one token."""
        agent = require_actor(actor, role, "agent")
        if not str(idempotency_key or "").strip():
            raise ApiError(400, "幂等键不能为空")
        check_at = parse_time(at)
        denial: str | None = None
        with self.store.write():
            # Replay the first token before any state gate so retries are stable.
            prior = self.store.get_presentation(delegation_id, idempotency_key)
            if prior:
                self.store.audit(agent, "delegation.present.replay", "delegation", delegation_id,
                                 {"idempotency_key": idempotency_key, "presentation_id": prior["id"]})
                return {
                    "token": prior["token"], "payload": json.loads(prior["payload_json"]),
                    "signature": prior["signature"],
                    "disclosed_fields": json.loads(prior["disclosed_fields_json"]),
                    "idempotent_replay": True,
                }
            delegation = self.store.get_delegation(delegation_id)
            if delegation is None:
                raise ApiError(404, "委托不存在")
            credential = self._credential(delegation["credential_id"])
            denial = DelegationPolicy.presentation_block(
                issuer_frozen=self.store.is_issuer_frozen(credential["issuer"]),
                credential=credential, delegation=delegation, agent_id=agent, at=check_at,
            )
            if denial:
                self.store.audit(agent, "delegation.present.denied", "delegation", delegation_id,
                                 {"reason": denial, "idempotency_key": idempotency_key})
            else:
                allowed = json.loads(delegation["visible_fields_json"])
                disclosed = disclosed_fields if disclosed_fields is not None else allowed
                if len(disclosed) != len(set(disclosed)) or any(name not in allowed for name in disclosed):
                    raise ApiError(400, "披露字段超出委托可见范围或重复")
                claims = json.loads(credential["claims_json"])
                payload = {
                    "credential_id": credential["id"],
                    "template_id": credential["template_id"],
                    "issuer": credential["issuer"],
                    "holder_id": credential["holder_id"],
                    "agent_id": agent,
                    "presented_by": agent,
                    "delegation_id": delegation["id"],
                    "claims": {name: claims[name] for name in disclosed},
                    "valid_until": credential["valid_until"],
                    "delegation_expires_at": delegation["expires_at"],
                    "key_version": delegation["key_version"],
                }
                token, signature = sign_token(self.conn, payload, credential["issuer"], delegation["key_version"])
                try:
                    presentation_id = self.store.insert_presentation(
                        delegation["id"], idempotency_key, disclosed, token, payload, signature
                    )
                except sqlite3.IntegrityError as exc:
                    raise ApiError(409, "并发提交冲突，请用相同幂等键重试") from exc
                self.store.audit(agent, "delegation.present", "delegation", delegation["id"],
                                 {"presentation_id": presentation_id, "idempotency_key": idempotency_key,
                                  "disclosed_fields": disclosed, "key_version": delegation["key_version"]})
        if denial:
            raise ApiError(409, BLOCK_REASONS[denial], denial)
        return {"token": token, "payload": payload, "signature": signature,
                "disclosed_fields": disclosed, "idempotent_replay": False}

    def state(self) -> dict:
        delegations = [self._delegation_dict(row) for row in self.store.list_delegations()]
        freezes = [dict(row) for row in self.conn.execute("SELECT issuer,frozen_at FROM issuer_freezes ORDER BY issuer")]
        presentations = [
            {"id": row["id"], "delegation_id": row["delegation_id"], "idempotency_key": row["idempotency_key"],
             "disclosed_fields": json.loads(row["disclosed_fields_json"]), "created_at": row["created_at"]}
            for row in self.conn.execute(
                "SELECT id,delegation_id,idempotency_key,disclosed_fields_json,created_at "
                "FROM delegation_presentations ORDER BY id DESC"
            )
        ]
        return {"delegations": delegations, "issuer_freezes": freezes, "delegation_presentations": presentations}


class FreezeService:
    """Issuer-wide freeze flag; it never mutates credentials, delegations or pending items."""

    def __init__(self, store: Store):
        self.store = store

    def freeze(self, actor: str | None, role: str | None, issuer: str) -> dict:
        actor = require_actor(actor, role, "issuer")
        if actor != issuer:
            raise ApiError(403, "只能冻结本机构")
        already = self.store.is_issuer_frozen(issuer)
        with self.store.write():
            self.store.freeze_issuer(issuer)
            if not already:
                self.store.audit(actor, "issuer.freeze", "issuer", issuer, {})
        return {"issuer": issuer, "frozen": True}

    def unfreeze(self, actor: str | None, role: str | None, issuer: str) -> dict:
        actor = require_actor(actor, role, "issuer")
        if actor != issuer:
            raise ApiError(403, "只能解冻本机构")
        with self.store.write():
            self.store.unfreeze_issuer(issuer)
            # Only items still valid now come back; expired/revoked records stay as they were.
            restored_credentials = self.store.restorable_credential_ids(issuer, now())
            restored_delegations = self.store.restorable_delegation_ids(issuer, now())
            self.store.audit(actor, "issuer.unfreeze", "issuer", issuer,
                             {"restored_credentials": restored_credentials,
                              "restored_delegations": restored_delegations})
        return {"issuer": issuer, "frozen": False,
                "restored_credentials": restored_credentials, "restored_delegations": restored_delegations}


class Handler(BaseHTTPRequestHandler):
    service: CredentialService
    delegations: DelegationService
    freezes: FreezeService

    def log_message(self, fmt: str, *args: object) -> None:
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    def _json(self, status: int, body: dict) -> None:
        data = json.dumps(body, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _body(self) -> dict:
        length = int(self.headers.get("Content-Length", "0"))
        if not length:
            return {}
        try:
            return json.loads(self.rfile.read(length))
        except json.JSONDecodeError as exc:
            raise ApiError(400, "JSON 请求体无效") from exc

    def _parts(self) -> list[str]:
        return [part for part in urlparse(self.path).path.strip("/").split("/") if part]

    def do_GET(self) -> None:
        try:
            parts = self._parts()
            if parts == ["health"] or parts == ["api", "health"]:
                return self._json(200, {"status": "ok"})
            if parts == ["api", "state"]:
                state = self.service.state()
                state.update(self.delegations.state())
                return self._json(200, state)
            if not parts:
                page = (Path(__file__).parent / "static" / "index.html").read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(page)))
                self.end_headers()
                self.wfile.write(page)
                return
            raise ApiError(404, "接口不存在")
        except ApiError as exc:
            self._json(exc.status, {"error": exc.message, **({"code": exc.code} if exc.code else {})})
        except Exception as exc:
            self._json(500, {"error": str(exc)})

    def do_POST(self) -> None:
        try:
            parts = self._parts()
            body = self._body()
            actor, role = self.headers.get("X-Actor"), self.headers.get("X-Role")
            if parts == ["api", "keys", "rotate"]:
                result = self.service.rotate_key(actor, role, body.get("issuer", actor or ""))
            elif parts == ["api", "templates"]:
                result = self.service.create_template(actor, role, body.get("code", ""), body.get("name", ""), body.get("fields", []), int(body.get("validity_days", 1)))
            elif parts == ["api", "credentials"]:
                result = self.service.issue(actor, role, int(body.get("template_id", 0)), body.get("holder_id", ""), body.get("claims", {}), body.get("idempotency_key", ""), body.get("valid_until"))
            elif len(parts) == 4 and parts[:2] == ["api", "credentials"] and parts[3] == "revoke":
                result = self.service.revoke(actor, role, int(parts[2]), body.get("reason", ""), body.get("effective_at"))
            elif len(parts) == 4 and parts[:2] == ["api", "credentials"] and parts[3] == "dispute":
                result = self.service.dispute(actor, role, int(parts[2]), body.get("reason", ""))
            elif len(parts) == 4 and parts[:2] == ["api", "credentials"] and parts[3] == "present":
                result = self.service.present(actor, role, int(parts[2]), body.get("disclosed_fields"))
            elif len(parts) == 4 and parts[:2] == ["api", "disputes"] and parts[3] == "resolve":
                result = self.service.resolve_dispute(actor, role, int(parts[2]), body.get("decision", ""), body.get("resolution", ""))
            elif parts == ["api", "verify"]:
                result = self.service.verify(body.get("token", ""), body.get("at"), bool(body.get("online", True)))
            elif parts == ["api", "delegations"]:
                result = self.delegations.register(
                    actor, role, int(body.get("credential_id", 0)), body.get("agent_id", ""),
                    body.get("visible_fields", []), body.get("expires_at", "")
                )
            elif len(parts) == 4 and parts[:2] == ["api", "delegations"] and parts[3] == "present":
                result = self.delegations.present(
                    actor, role, int(parts[2]), body.get("idempotency_key", ""),
                    body.get("disclosed_fields"), body.get("at")
                )
            elif len(parts) == 4 and parts[:2] == ["api", "delegations"] and parts[3] == "revoke":
                result = self.delegations.revoke(actor, role, int(parts[2]), body.get("reason", ""))
            elif parts == ["api", "issuer", "freeze"]:
                result = self.freezes.freeze(actor, role, body.get("issuer", actor or ""))
            elif parts == ["api", "issuer", "unfreeze"]:
                result = self.freezes.unfreeze(actor, role, body.get("issuer", actor or ""))
            else:
                raise ApiError(404, "接口不存在")
            self._json(200, result)
        except ApiError as exc:
            self._json(exc.status, {"error": exc.message, **({"code": exc.code} if exc.code else {})})
        except (ValueError, TypeError, sqlite3.IntegrityError) as exc:
            self._json(400, {"error": str(exc)})
        except Exception as exc:
            self._json(500, {"error": str(exc)})


def run(port: int, db_path: str, seed: bool) -> None:
    store = Store(db_path)
    service = CredentialService(store)
    Handler.service = service
    Handler.delegations = DelegationService(store)
    Handler.freezes = FreezeService(store)
    if seed:
        service.seed()
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"digital credentials listening on http://127.0.0.1:{port}")
    server.serve_forever()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8211)
    parser.add_argument("--db", default=str(DB_PATH))
    parser.add_argument("--init", action="store_true")
    parser.add_argument("--seed", action="store_true")
    args = parser.parse_args()
    if args.init:
        Store(args.db).close()
    if not any((args.seed, not args.init)):
        return
    run(args.port, args.db, args.seed)


if __name__ == "__main__":
    main()
