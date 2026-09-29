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


class ApiError(Exception):
    def __init__(self, status: int, message: str, reason: str | None = None):
        super().__init__(message)
        self.status = status
        self.message = message
        self.reason = reason or message


# ---------------------------------------------------------------------------
# 状态判定层（纯函数，不访问数据库）：请求入口与记录保存之外的独立判定
# ---------------------------------------------------------------------------

PRESENT_FAILURES = {
    "issuer_frozen": (409, "签发机构已冻结，暂停出示"),
    "credential_revoked": (409, "凭证已撤销"),
    "credential_disputed": (409, "凭证撤销争议处理中"),
    "credential_expired": (409, "凭证已过期"),
    "delegation_ended": (409, "委托已结束"),
    "delegation_expired": (409, "委托已超过截止时间"),
}


def evaluate_presentation(
    *,
    frozen: bool,
    credential_status: str,
    revocation_effective_at: datetime | None,
    credential_valid_until: datetime,
    delegation_status: str,
    delegation_expires_at: datetime,
    at: datetime,
) -> str | None:
    """返回 None 表示可以出示；否则返回拒绝原因码。各原因按优先级独立判定。"""
    if frozen:
        return "issuer_frozen"
    if credential_status == "revoked" and revocation_effective_at is not None and at >= revocation_effective_at:
        return "credential_revoked"
    if credential_status == "disputed":
        return "credential_disputed"
    if at >= credential_valid_until:
        return "credential_expired"
    if delegation_status != "active":
        return "delegation_ended"
    if at >= delegation_expires_at:
        return "delegation_expired"
    return None


class Store:
    def __init__(self, path: str | os.PathLike[str] = DB_PATH):
        self.path = str(path)
        self.conn = sqlite3.connect(self.path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.init_schema()

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
            CREATE TABLE IF NOT EXISTS issuer_freezes (
              issuer TEXT PRIMARY KEY,
              frozen INTEGER NOT NULL CHECK(frozen IN (0,1)),
              reason TEXT,
              frozen_at TEXT,
              unfrozen_at TEXT
            );
            CREATE TABLE IF NOT EXISTS delegations (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              credential_id INTEGER NOT NULL REFERENCES credentials(id),
              holder_id TEXT NOT NULL,
              agent_id TEXT NOT NULL,
              visible_fields_json TEXT NOT NULL,
              created_at TEXT NOT NULL,
              expires_at TEXT NOT NULL,
              status TEXT NOT NULL CHECK(status IN ('active','ended')),
              end_reason TEXT,
              ended_at TEXT,
              key_version INTEGER NOT NULL
            );
            CREATE UNIQUE INDEX IF NOT EXISTS one_open_delegation
              ON delegations(holder_id, agent_id)
              WHERE status='active';
            CREATE TABLE IF NOT EXISTS delegation_presentations (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              delegation_id INTEGER NOT NULL REFERENCES delegations(id),
              idempotency_key TEXT NOT NULL,
              token TEXT NOT NULL,
              signature TEXT NOT NULL,
              disclosed_fields_json TEXT NOT NULL,
              created_at TEXT NOT NULL,
              UNIQUE(delegation_id, idempotency_key)
            );
            """
        )
        self.conn.commit()

    def audit(self, actor: str, action: str, entity_type: str, entity_id: object, details: dict) -> None:
        self.conn.execute(
            "INSERT INTO audit_log(at,actor,action,entity_type,entity_id,details_json) VALUES(?,?,?,?,?,?)",
            (iso(), actor, action, entity_type, str(entity_id), json.dumps(details, ensure_ascii=False)),
        )

    # -- 签发方冻结 ----------------------------------------------------------

    def set_freeze(self, issuer: str, frozen: bool, reason: str | None) -> None:
        self.conn.execute(
            """INSERT INTO issuer_freezes(issuer,frozen,reason,frozen_at,unfrozen_at)
               VALUES(?,?,?,?,NULL)
               ON CONFLICT(issuer) DO UPDATE SET frozen=excluded.frozen, reason=excluded.reason,
                 frozen_at=excluded.frozen_at, unfrozen_at=excluded.unfrozen_at""",
            (issuer, int(frozen), reason, iso() if frozen else None),
        )
        if not frozen:
            self.conn.execute("UPDATE issuer_freezes SET unfrozen_at=? WHERE issuer=?", (iso(), issuer))

    def is_frozen(self, issuer: str) -> bool:
        row = self.conn.execute("SELECT frozen FROM issuer_freezes WHERE issuer=?", (issuer,)).fetchone()
        return bool(row and row["frozen"])

    def freeze_row(self, issuer: str) -> sqlite3.Row | None:
        return self.conn.execute("SELECT * FROM issuer_freezes WHERE issuer=?", (issuer,)).fetchone()

    # -- 委托 ----------------------------------------------------------------

    def find_open_delegation(self, holder_id: str, agent_id: str) -> sqlite3.Row | None:
        return self.conn.execute(
            "SELECT * FROM delegations WHERE holder_id=? AND agent_id=? AND status='active'",
            (holder_id, agent_id),
        ).fetchone()

    def delegation(self, delegation_id: int) -> sqlite3.Row | None:
        return self.conn.execute("SELECT * FROM delegations WHERE id=?", (delegation_id,)).fetchone()

    def end_delegation(self, delegation_id: int, reason: str) -> None:
        self.conn.execute(
            "UPDATE delegations SET status='ended', end_reason=?, ended_at=? WHERE id=? AND status='active'",
            (reason, iso(), delegation_id),
        )

    def insert_delegation(
        self, credential_id: int, holder_id: str, agent_id: str, visible_fields: list[str],
        expires_at: datetime, key_version: int,
    ) -> int:
        cur = self.conn.execute(
            """INSERT INTO delegations(credential_id,holder_id,agent_id,visible_fields_json,created_at,expires_at,status,key_version)
               VALUES(?,?,?,?,?,?,'active',?)""",
            (credential_id, holder_id, agent_id, json.dumps(visible_fields, ensure_ascii=False),
             iso(), iso(expires_at), key_version),
        )
        return int(cur.lastrowid)

    def list_delegations(self) -> list[sqlite3.Row]:
        return list(self.conn.execute("SELECT * FROM delegations ORDER BY id DESC"))

    # -- 代出示令牌（幂等记录） ----------------------------------------------

    def find_presentation(self, delegation_id: int, idempotency_key: str) -> sqlite3.Row | None:
        return self.conn.execute(
            "SELECT * FROM delegation_presentations WHERE delegation_id=? AND idempotency_key=?",
            (delegation_id, idempotency_key),
        ).fetchone()

    def save_presentation(
        self, delegation_id: int, idempotency_key: str, token: str, signature: str, disclosed_fields: list[str],
    ) -> int:
        cur = self.conn.execute(
            """INSERT INTO delegation_presentations(delegation_id,idempotency_key,token,signature,disclosed_fields_json,created_at)
               VALUES(?,?,?,?,?,?)""",
            (delegation_id, idempotency_key, token, signature,
             json.dumps(disclosed_fields, ensure_ascii=False), iso()),
        )
        return int(cur.lastrowid)

    def close(self) -> None:
        self.conn.close()


class CredentialService:
    """Credential issuance and verification with small, explicit trust boundaries."""

    def __init__(self, store: Store):
        self.store = store
        self.conn = store.conn
        # 串行化登记与代出示提交：配合唯一索引保证并发提交只成功一次
        self._register_lock = threading.RLock()
        self._present_lock = threading.RLock()

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
        with self.conn:
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
            with self.conn:
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
            with self.conn:
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
        with self.conn:
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
        with self.conn:
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
        with self.conn:
            self.conn.execute("UPDATE disputes SET status=?,resolution=?,resolved_at=? WHERE id=?", (dispute_status, resolution, iso(), dispute_id))
            self.conn.execute("UPDATE credentials SET status=? WHERE id=?", (new_status, credential["id"]))
            self.store.audit(actor, "dispute.resolve", "dispute", dispute_id, {"decision": decision, "credential_status": new_status})
        return {"id": dispute_id, "status": decision, "credential_status": new_status, "resolution": resolution}

    def present(self, actor: str | None, role: str | None, credential_id: int, disclosed_fields: list[str] | None) -> dict:
        actor = self._required_actor(actor, role, "holder")
        credential = self._row("credentials", credential_id)
        if credential["holder_id"] != actor:
            raise ApiError(403, "不能出示他人的凭证")
        if self.store.is_frozen(credential["issuer"]):
            raise ApiError(409, PRESENT_FAILURES["issuer_frozen"][1], reason="issuer_frozen")
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
        key = self.conn.execute(
            "SELECT secret_hex FROM key_versions WHERE issuer=? AND version=?", (credential["issuer"], credential["key_version"])
        ).fetchone()
        signature = hmac.new(bytes.fromhex(key["secret_hex"]), canonical(payload), hashlib.sha256).hexdigest()
        token = base64.urlsafe_b64encode(canonical({"payload": payload, "signature": signature})).decode().rstrip("=")
        self.store.audit(actor, "credential.present", "credential", credential_id, {"disclosed_fields": disclosed})
        self.conn.commit()
        return {"token": token, "payload": payload, "signature": signature, "disclosed_fields": disclosed}

    # ------------------------------------------------------------------
    # 受控代出示
    # ------------------------------------------------------------------

    @staticmethod
    def _failure(reason: str) -> ApiError:
        status, message = PRESENT_FAILURES[reason]
        return ApiError(status, message, reason=reason)

    def _sign(self, issuer: str, key_version: int, payload: dict) -> str:
        # 始终按指定版本的密钥验证/签名，密钥轮换不影响老委托
        key = self.conn.execute(
            "SELECT secret_hex FROM key_versions WHERE issuer=? AND version=?", (issuer, key_version)
        ).fetchone()
        if not key:
            raise ApiError(409, "无法找到签发密钥版本")
        return hmac.new(bytes.fromhex(key["secret_hex"]), canonical(payload), hashlib.sha256).hexdigest()

    def register_delegation(
        self, actor: str | None, role: str | None, credential_id: int,
        agent_id: str, visible_fields: list[str], expires_at: str,
    ) -> dict:
        actor = self._required_actor(actor, role, "holder")
        if not str(agent_id).strip():
            raise ApiError(400, "代理人不能为空")
        credential = self._row("credentials", credential_id)
        if credential["holder_id"] != actor:
            raise ApiError(403, "只能为自己持有的凭证登记代理人")
        if credential["status"] == "revoked":
            raise ApiError(409, "凭证已撤销，不能登记委托")
        if credential["status"] == "disputed":
            raise ApiError(409, "凭证撤销争议处理中，不能登记委托")
        template = self._row("templates", credential["template_id"])
        allowed = [field["name"] for field in json.loads(template["fields_json"])]
        fields = list(visible_fields or [])
        if not fields or len(fields) != len(set(fields)) or any(name not in allowed for name in fields):
            raise ApiError(400, "可见字段必须是模板字段的非空、无重复子集")
        try:
            expiry = parse_time(expires_at)
        except (ValueError, TypeError) as exc:
            raise ApiError(400, "截止时间格式无效") from exc
        if expiry <= now():
            raise ApiError(400, "截止时间必须晚于当前时间")
        if expiry > parse_time(credential["valid_until"]):
            raise ApiError(400, "委托截止时间不能晚于凭证有效期")
        agent_id = str(agent_id).strip()
        with self._register_lock:
            try:
                with self.conn:
                    previous = self.store.find_open_delegation(actor, agent_id)
                    if previous:
                        # 同一代理人只保留一份未结束委托：旧委托结束
                        self.store.end_delegation(previous["id"], "superseded")
                    # 新委托固定到当前生效密钥版本；轮换后老委托仍按签发时版本验证
                    key_version = int(self._active_key(credential["issuer"])["version"])
                    delegation_id = self.store.insert_delegation(
                        credential_id, actor, agent_id, fields, expiry, key_version
                    )
                    self.store.audit(actor, "delegation.register", "delegation", delegation_id,
                                     {"credential_id": credential_id, "agent_id": agent_id,
                                      "visible_fields": fields, "expires_at": iso(expiry),
                                      "key_version": key_version, "superseded": previous["id"] if previous else None})
            except sqlite3.IntegrityError as exc:
                raise ApiError(409, "该代理人已有未结束委托") from exc
        return self._delegation_dict(self.store.delegation(delegation_id))

    def agent_present(
        self, actor: str | None, role: str | None, delegation_id: int, idempotency_key: str,
    ) -> dict:
        actor = self._required_actor(actor, role, "agent")
        if not str(idempotency_key).strip():
            raise ApiError(400, "幂等键不能为空")
        with self._present_lock:
            # 重复请求（无论当前状态如何）一律沿用首次成功的令牌
            saved = self.store.find_presentation(delegation_id, idempotency_key)
            if saved:
                row = self.store.delegation(delegation_id)
                payload = json.loads(base64.urlsafe_b64decode(saved["token"] + "=" * (-len(saved["token"]) % 4)))["payload"]
                self.conn.commit()
                return {"token": saved["token"], "payload": payload, "signature": saved["signature"],
                        "disclosed_fields": json.loads(saved["disclosed_fields_json"]), "replayed": True,
                        "delegation_id": delegation_id}
            delegation = self.store.delegation(delegation_id)
            if not delegation:
                raise ApiError(404, "委托不存在")
            if delegation["agent_id"] != actor:
                raise ApiError(403, "只有登记的代理人可以使用该委托")
            credential = self._row("credentials", delegation["credential_id"])
            check_at = now()
            reason = evaluate_presentation(
                frozen=self.store.is_frozen(credential["issuer"]),
                credential_status=credential["status"],
                revocation_effective_at=parse_time(credential["revocation_effective_at"]) if credential["revocation_effective_at"] else None,
                credential_valid_until=parse_time(credential["valid_until"]),
                delegation_status=delegation["status"],
                delegation_expires_at=parse_time(delegation["expires_at"]),
                at=check_at,
            )
            if reason:
                raise self._failure(reason)
            claims = json.loads(credential["claims_json"])
            visible_fields = json.loads(delegation["visible_fields_json"])
            visible = {name: claims[name] for name in visible_fields}
            payload = {
                "credential_id": credential["id"],
                "template_id": credential["template_id"],
                "issuer": credential["issuer"],
                "holder_id": credential["holder_id"],
                "presented_by": "agent",
                "agent_id": delegation["agent_id"],
                "delegation_id": delegation["id"],
                "claims": visible,
                "valid_until": credential["valid_until"],
                "delegation_expires_at": delegation["expires_at"],
                # 委托登记时的密钥版本；轮换后老委托继续按此版本验证
                "key_version": delegation["key_version"],
            }
            signature = self._sign(credential["issuer"], int(delegation["key_version"]), payload)
            token = base64.urlsafe_b64encode(
                canonical({"payload": payload, "signature": signature})
            ).decode().rstrip("=")
            try:
                with self.conn:
                    self.store.save_presentation(delegation_id, idempotency_key, token, signature, visible_fields)
                    self.store.audit(actor, "delegation.present", "delegation", delegation_id,
                                     {"credential_id": credential["id"], "idempotency_key": idempotency_key,
                                      "disclosed_fields": visible_fields})
            except sqlite3.IntegrityError as exc:
                # 并发提交：只成功一次，其余沿用首次令牌
                saved = self.store.find_presentation(delegation_id, idempotency_key)
                if saved:
                    payload = json.loads(base64.urlsafe_b64decode(saved["token"] + "=" * (-len(saved["token"]) % 4)))["payload"]
                    return {"token": saved["token"], "payload": payload, "signature": saved["signature"],
                            "disclosed_fields": json.loads(saved["disclosed_fields_json"]), "replayed": True,
                            "delegation_id": delegation_id}
                raise ApiError(409, "并发出示冲突，请用相同幂等键重试") from exc
        return {"token": token, "payload": payload, "signature": signature,
                "disclosed_fields": visible_fields, "replayed": False, "delegation_id": delegation_id}

    def freeze_issuer(self, actor: str | None, role: str | None, issuer: str, reason: str) -> dict:
        actor = self._required_actor(actor, role, "issuer")
        if actor != issuer:
            raise ApiError(403, "只能冻结本机构")
        if not reason.strip():
            raise ApiError(400, "冻结原因不能为空")
        with self.conn:
            self.store.set_freeze(issuer, True, reason)
            self.store.audit(actor, "issuer.freeze", "issuer", issuer, {"reason": reason})
            todos = self.conn.execute(
                """SELECT d.id FROM delegations d JOIN credentials c ON c.id=d.credential_id
                   WHERE c.issuer=? AND d.status='active'""", (issuer,)).fetchall()
        # 冻结后待办保留：委托与争议记录均不删除、不改状态，仅停用出示
        return {"issuer": issuer, "frozen": True, "reason": reason, "open_delegations_retained": len(todos)}

    def unfreeze_issuer(self, actor: str | None, role: str | None, issuer: str) -> dict:
        actor = self._required_actor(actor, role, "issuer")
        if actor != issuer:
            raise ApiError(403, "只能解冻本机构")
        row = self.store.freeze_row(issuer)
        if not row or not row["frozen"]:
            raise ApiError(409, "本机构当前未冻结")
        check_at = now()
        restored: list[int] = []
        skipped: list[dict] = []
        with self.conn:
            active = self.conn.execute(
                """SELECT d.* FROM delegations d JOIN credentials c ON c.id=d.credential_id
                   WHERE c.issuer=? AND d.status='active'""", (issuer,)).fetchall()
            for d in active:
                credential = self._row("credentials", d["credential_id"])
                reason = evaluate_presentation(
                    frozen=False,
                    credential_status=credential["status"],
                    revocation_effective_at=parse_time(credential["revocation_effective_at"]) if credential["revocation_effective_at"] else None,
                    credential_valid_until=parse_time(credential["valid_until"]),
                    delegation_status=d["status"],
                    delegation_expires_at=parse_time(d["expires_at"]),
                    at=check_at,
                )
                if reason is None:
                    restored.append(d["id"])
                else:
                    # 解冻只恢复当前仍有效的凭证和委托；其余继续按原因拒绝
                    skipped.append({"delegation_id": d["id"], "reason": reason})
            self.store.set_freeze(issuer, False, None)
            self.store.audit(actor, "issuer.unfreeze", "issuer", issuer,
                             {"restored_delegations": restored, "not_restored": skipped})
        return {"issuer": issuer, "frozen": False, "restored_delegations": restored, "not_restored": skipped}

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
        # 令牌携带签发时密钥版本：老委托/老令牌轮换后仍按原版本验签
        key_version = int(payload.get("key_version", credential["key_version"]))
        key = self.conn.execute(
            "SELECT * FROM key_versions WHERE issuer=? AND version=?", (credential["issuer"], key_version)
        ).fetchone()
        if not key:
            raise ApiError(409, "无法找到签发密钥版本")
        expected = hmac.new(bytes.fromhex(key["secret_hex"]), canonical(payload), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, str(supplied_signature)):
            raise ApiError(400, "凭证签名无效")
        check_at = parse_time(at)
        expiration = parse_time(credential["valid_until"])
        delegation = None
        if payload.get("presented_by") == "agent":
            delegation = self.store.delegation(int(payload.get("delegation_id", 0)))
        result = {
            "valid": True, "status": "valid", "key_retired": key["status"] == "retired",
            "claims": payload.get("claims", {}),
            "presented_by": payload.get("presented_by", "holder"),
        }
        if delegation:
            result["delegation_id"] = delegation["id"]
            result["agent_id"] = payload.get("agent_id")
        # 代出示：委托自身状态优先于凭证状态，各自原因独立给出
        if online and delegation is not None and self.store.is_frozen(credential["issuer"]):
            result.update(valid=False, status="issuer_frozen", reason=PRESENT_FAILURES["issuer_frozen"][1])
        elif delegation is not None and delegation["status"] != "active":
            result.update(valid=False, status="delegation_ended",
                          reason=PRESENT_FAILURES["delegation_ended"][1])
        elif delegation is not None and check_at >= parse_time(delegation["expires_at"]):
            result.update(valid=False, status="delegation_expired",
                          reason=PRESENT_FAILURES["delegation_expired"][1])
        elif check_at >= expiration:
            result.update(valid=False, status="expired", reason="凭证已过期")
        elif credential["status"] == "disputed":
            result.update(valid=False, status="disputed", reason="撤销决定正在争议复核")
        elif credential["status"] == "revoked":
            effective = parse_time(credential["revocation_effective_at"])
            if check_at >= effective:
                result.update(valid=False, status="revoked", reason=credential["revocation_reason"])
            else:
                result.update(status="valid_until_revocation", revocation_starts_at=credential["revocation_effective_at"])
        if not online:
            result["offline"] = True
            result["revocation_freshness"] = "needs_online_check"
            # 离线模式仍可依据令牌内的截止时间判定委托过期
            if result["valid"] and delegation is not None and check_at >= parse_time(delegation["expires_at"]):
                result.update(valid=False, status="delegation_expired",
                              reason=PRESENT_FAILURES["delegation_expired"][1])
            elif result["valid"]:
                result["status"] = "valid_offline"
        self.conn.commit()
        return result

    def _credential_dict(self, row: sqlite3.Row) -> dict:
        return {
            "id": row["id"], "template_id": row["template_id"], "issuer": row["issuer"], "holder_id": row["holder_id"],
            "claims": json.loads(row["claims_json"]), "issued_at": row["issued_at"], "valid_until": row["valid_until"],
            "status": row["status"], "key_version": row["key_version"], "revocation_reason": row["revocation_reason"],
            "revocation_effective_at": row["revocation_effective_at"],
        }

    def _delegation_dict(self, row: sqlite3.Row) -> dict:
        return {
            "id": row["id"], "credential_id": row["credential_id"], "holder_id": row["holder_id"],
            "agent_id": row["agent_id"], "visible_fields": json.loads(row["visible_fields_json"]),
            "created_at": row["created_at"], "expires_at": row["expires_at"], "status": row["status"],
            "end_reason": row["end_reason"], "ended_at": row["ended_at"], "key_version": row["key_version"],
        }

    def state(self) -> dict:
        credentials = [self._credential_dict(row) for row in self.conn.execute("SELECT * FROM credentials ORDER BY id DESC")]
        templates = [dict(row) for row in self.conn.execute("SELECT id,issuer,code,name,status,validity_days FROM templates ORDER BY id DESC")]
        delegations = [self._delegation_dict(row) for row in self.store.list_delegations()]
        freezes = [dict(row) for row in self.conn.execute("SELECT issuer,frozen,reason,frozen_at,unfrozen_at FROM issuer_freezes ORDER BY issuer")]
        audits = [dict(row) for row in self.conn.execute("SELECT at,actor,action,entity_type,entity_id,details_json FROM audit_log ORDER BY id DESC LIMIT 30")]
        return {"templates": templates, "credentials": credentials,
                "delegations": delegations, "issuer_freezes": freezes, "audits": audits}

    def seed(self) -> None:
        if not self.conn.execute("SELECT id FROM key_versions LIMIT 1").fetchone():
            self.rotate_key("issuer-demo", "issuer", "issuer-demo")
        if not self.conn.execute("SELECT id FROM templates LIMIT 1").fetchone():
            self.create_template("issuer-demo", "issuer", "student-v1", "学生身份", [{"name": "name", "required": True}, {"name": "program", "required": True}, {"name": "degree", "required": False}], 365)


class Handler(BaseHTTPRequestHandler):
    service: CredentialService

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
                return self._json(200, self.service.state())
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
            self._json(exc.status, {"error": exc.message})
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
            elif len(parts) == 4 and parts[:2] == ["api", "credentials"] and parts[3] == "delegations":
                result = self.service.register_delegation(
                    actor, role, int(parts[2]), body.get("agent_id", ""),
                    body.get("visible_fields", []), body.get("expires_at", ""))
            elif len(parts) == 4 and parts[:2] == ["api", "delegations"] and parts[3] == "present":
                result = self.service.agent_present(actor, role, int(parts[2]), body.get("idempotency_key", ""))
            elif parts == ["api", "issuer", "freeze"]:
                result = self.service.freeze_issuer(actor, role, actor or "", body.get("reason", ""))
            elif parts == ["api", "issuer", "unfreeze"]:
                result = self.service.unfreeze_issuer(actor, role, actor or "")
            elif len(parts) == 4 and parts[:2] == ["api", "disputes"] and parts[3] == "resolve":
                result = self.service.resolve_dispute(actor, role, int(parts[2]), body.get("decision", ""), body.get("resolution", ""))
            elif parts == ["api", "verify"]:
                result = self.service.verify(body.get("token", ""), body.get("at"), bool(body.get("online", True)))
            else:
                raise ApiError(404, "接口不存在")
            self._json(200, result)
        except ApiError as exc:
            self._json(exc.status, {"error": exc.message, "reason": exc.reason})
        except (ValueError, TypeError, sqlite3.IntegrityError) as exc:
            self._json(400, {"error": str(exc)})
        except Exception as exc:
            self._json(500, {"error": str(exc)})


def run(port: int, db_path: str, seed: bool) -> None:
    store = Store(db_path)
    service = CredentialService(store)
    if seed:
        service.seed()
    Handler.service = service
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
