"""AI-specific SQLite tables. Kept separate from the document store schema."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class AIStore:
    def __init__(self, db_path: Path):
        self.db_path = Path(db_path)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=15, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=15000")
        return conn

    def initialize(self) -> None:
        with self._connect() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS ai_config (
                    id INTEGER PRIMARY KEY CHECK (id = 1), provider TEXT NOT NULL,
                    base_url TEXT NOT NULL, model TEXT NOT NULL, api_key_ciphertext TEXT,
                    enabled INTEGER NOT NULL DEFAULT 1,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS conversations (
                    id TEXT PRIMARY KEY, title TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, conversation_id TEXT NOT NULL,
                    role TEXT NOT NULL, content TEXT NOT NULL, created_at TEXT NOT NULL,
                    FOREIGN KEY(conversation_id) REFERENCES conversations(id) ON DELETE CASCADE
                );
                CREATE TABLE IF NOT EXISTS ai_usage (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, conversation_id TEXT, provider TEXT NOT NULL,
                    model TEXT NOT NULL, prompt_tokens INTEGER NOT NULL DEFAULT 0,
                    completion_tokens INTEGER NOT NULL DEFAULT 0, total_tokens INTEGER NOT NULL DEFAULT 0,
                    status TEXT NOT NULL DEFAULT 'completed', usage_known INTEGER NOT NULL DEFAULT 0,
                    usage_json TEXT,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_ai_usage_created_at ON ai_usage(created_at);
                CREATE INDEX IF NOT EXISTS idx_messages_conversation ON messages(conversation_id, id);
                CREATE TABLE IF NOT EXISTS ai_tool_audit (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, request_id TEXT NOT NULL,
                    tool_id TEXT NOT NULL, risk TEXT NOT NULL, status TEXT NOT NULL,
                    arguments_json TEXT, result_json TEXT, created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_ai_tool_audit_created_at ON ai_tool_audit(created_at);
                CREATE TABLE IF NOT EXISTS ai_tool_confirmations (
                    id TEXT PRIMARY KEY, tool_id TEXT NOT NULL, arguments_json TEXT NOT NULL,
                    preview_json TEXT NOT NULL, status TEXT NOT NULL,
                    expires_at TEXT NOT NULL, created_at TEXT NOT NULL,
                    confirmed_at TEXT, result_json TEXT
                );
                CREATE TABLE IF NOT EXISTS ai_notifications (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT NOT NULL,
                    title TEXT NOT NULL, content TEXT NOT NULL, payload_json TEXT,
                    dedupe_key TEXT NOT NULL UNIQUE, created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_ai_notifications_created_at ON ai_notifications(created_at);
                CREATE TABLE IF NOT EXISTS ai_notification_deliveries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    notification_id INTEGER NOT NULL, channel TEXT NOT NULL, target TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'pending', attempts INTEGER NOT NULL DEFAULT 0,
                    last_error TEXT, sent_at TEXT, next_attempt_at TEXT NOT NULL, updated_at TEXT NOT NULL,
                    UNIQUE(notification_id, channel, target),
                    FOREIGN KEY(notification_id) REFERENCES ai_notifications(id) ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS idx_ai_deliveries_due
                    ON ai_notification_deliveries(status,next_attempt_at);
            """)
            # Existing phase-one databases may predate these audit fields.
            columns = {row["name"] for row in conn.execute("PRAGMA table_info(ai_usage)")}
            if "status" not in columns:
                conn.execute("ALTER TABLE ai_usage ADD COLUMN status TEXT NOT NULL DEFAULT 'completed'")
            if "usage_known" not in columns:
                conn.execute("ALTER TABLE ai_usage ADD COLUMN usage_known INTEGER NOT NULL DEFAULT 0")
            if "usage_json" not in columns:
                conn.execute("ALTER TABLE ai_usage ADD COLUMN usage_json TEXT")
            config_columns = {row["name"] for row in conn.execute("PRAGMA table_info(ai_config)")}
            if "enabled" not in config_columns:
                conn.execute("ALTER TABLE ai_config ADD COLUMN enabled INTEGER NOT NULL DEFAULT 1")

    def get_config(self) -> Optional[Dict[str, Any]]:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM ai_config WHERE id=1").fetchone()
        return dict(row) if row else None

    def save_config(self, provider: str, base_url: str, model: str, ciphertext: str, enabled: bool) -> None:
        with self._connect() as conn:
            conn.execute("""INSERT INTO ai_config(id,provider,base_url,model,api_key_ciphertext,enabled,updated_at)
                VALUES(1,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET provider=excluded.provider,
                base_url=excluded.base_url, model=excluded.model, api_key_ciphertext=excluded.api_key_ciphertext,
                enabled=excluded.enabled, updated_at=excluded.updated_at""", (provider, base_url, model, ciphertext, int(enabled), utc_now()))

    def delete_config(self) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM ai_config WHERE id=1")

    def create_conversation(self, conversation_id: str, title: Optional[str] = None) -> None:
        now = utc_now()
        with self._connect() as conn:
            conn.execute("INSERT OR IGNORE INTO conversations(id,title,created_at,updated_at) VALUES(?,?,?,?)",
                         (conversation_id, title, now, now))

    def list_conversations(self, limit: int = 20) -> list[Dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT id, title, created_at, updated_at FROM conversations "
                "ORDER BY updated_at DESC LIMIT ?", (int(limit),)
            ).fetchall()
        return [dict(row) for row in rows]

    def get_messages(self, conversation_id: str, limit: int = 40) -> list[Dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT role, content, created_at FROM messages "
                "WHERE conversation_id=? ORDER BY id DESC LIMIT ?",
                (conversation_id, int(limit)),
            ).fetchall()
        return [dict(row) for row in reversed(rows)]

    def add_message(self, conversation_id: str, role: str, content: str) -> None:
        with self._connect() as conn:
            conn.execute("INSERT INTO messages(conversation_id,role,content,created_at) VALUES(?,?,?,?)",
                         (conversation_id, role, content, utc_now()))
            conn.execute("UPDATE conversations SET updated_at=? WHERE id=?", (utc_now(), conversation_id))

    def add_usage(self, conversation_id: str, provider: str, model: str, usage: Dict[str, Any],
                  status: str = "completed") -> None:
        with self._connect() as conn:
            conn.execute("""INSERT INTO ai_usage(conversation_id,provider,model,prompt_tokens,completion_tokens,total_tokens,status,usage_known,usage_json,created_at)
                VALUES(?,?,?,?,?,?,?,?,?,?)""", (conversation_id, provider, model,
                int(usage.get("prompt_tokens") or 0), int(usage.get("completion_tokens") or 0),
                int(usage.get("total_tokens") or 0), status, int(bool(usage)),
                json.dumps(usage, separators=(",", ":")) if usage else None, utc_now()))

    def usage_summary(self) -> Dict[str, int]:
        with self._connect() as conn:
            row = conn.execute("SELECT COUNT(*) AS requests, COALESCE(SUM(prompt_tokens),0) AS prompt_tokens, "
                               "COALESCE(SUM(completion_tokens),0) AS completion_tokens, "
                               "COALESCE(SUM(total_tokens),0) AS total_tokens FROM ai_usage").fetchone()
            today = conn.execute(
                "SELECT COUNT(*) AS requests, COALESCE(SUM(total_tokens),0) AS total_tokens "
                "FROM ai_usage WHERE date(datetime(created_at, '+8 hours')) = date('now', '+8 hours')"
            ).fetchone()
        result = dict(row)
        result["today_requests"] = int(today["requests"] or 0)
        result["today_total_tokens"] = int(today["total_tokens"] or 0)
        return result

    def list_usage(self, limit: int = 50) -> list[Dict[str, Any]]:
        """Return a bounded metadata-only task list for the usage API."""
        try:
            bounded_limit = max(1, min(int(limit), 100))
        except (TypeError, ValueError):
            bounded_limit = 50
        fields = (
            "id, conversation_id, provider, model, prompt_tokens, completion_tokens, "
            "total_tokens, status, usage_known, created_at"
        )
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT {fields} FROM ai_usage ORDER BY id DESC LIMIT ?", (bounded_limit,)
            ).fetchall()
        return [dict(row) for row in rows]

    def usage_for_date(self, day: str) -> Dict[str, int]:
        """Return usage for an Asia/Shanghai calendar date without exposing secrets."""
        safe_day = str(day or "").strip()
        with self._connect() as conn:
            row = conn.execute(
                "SELECT COUNT(*) AS requests, "
                "COALESCE(SUM(prompt_tokens),0) AS prompt_tokens, "
                "COALESCE(SUM(completion_tokens),0) AS completion_tokens, "
                "COALESCE(SUM(total_tokens),0) AS total_tokens, "
                "COALESCE(SUM(CASE WHEN usage_known=0 THEN 1 ELSE 0 END),0) AS unknown_usage_requests "
                "FROM ai_usage WHERE date(datetime(created_at, '+8 hours')) = ?",
                (safe_day,),
            ).fetchone()
        return {key: int(row[key] or 0) for key in (
            "requests", "prompt_tokens", "completion_tokens", "total_tokens", "unknown_usage_requests"
        )}

    def add_tool_audit(self, request_id: str, tool_id: str, risk: str, status: str,
                       arguments: Dict[str, Any], result: Optional[Dict[str, Any]] = None) -> None:
        arguments_json = json.dumps(arguments, ensure_ascii=False, separators=(",", ":"))[:16000]
        result_json = json.dumps(result, ensure_ascii=False, separators=(",", ":"))[:32000] if result is not None else None
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO ai_tool_audit(request_id,tool_id,risk,status,arguments_json,result_json,created_at) "
                "VALUES(?,?,?,?,?,?,?)",
                (request_id, tool_id, risk, status, arguments_json, result_json, utc_now()),
            )

    def create_confirmation(self, confirmation_id: str, tool_id: str, arguments: Dict[str, Any],
                            preview: Dict[str, Any], expires_at: str) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO ai_tool_confirmations(id,tool_id,arguments_json,preview_json,status,expires_at,created_at) "
                "VALUES(?,?,?,?,?,?,?)",
                (confirmation_id, tool_id, json.dumps(arguments, ensure_ascii=False),
                 json.dumps(preview, ensure_ascii=False), "pending", expires_at, utc_now()),
            )

    def claim_confirmation(self, confirmation_id: str) -> Optional[Dict[str, Any]]:
        now = utc_now()
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT * FROM ai_tool_confirmations WHERE id=? AND status='pending' AND expires_at>=?",
                (confirmation_id, now),
            ).fetchone()
            if row is None:
                conn.execute("ROLLBACK")
                return None
            changed = conn.execute(
                "UPDATE ai_tool_confirmations SET status='executing', confirmed_at=? "
                "WHERE id=? AND status='pending'", (now, confirmation_id),
            ).rowcount
            if changed != 1:
                conn.execute("ROLLBACK")
                return None
            conn.execute("COMMIT")
        result = dict(row)
        result["arguments"] = json.loads(result.pop("arguments_json"))
        result["preview"] = json.loads(result.pop("preview_json"))
        return result

    def finish_confirmation(self, confirmation_id: str, status: str,
                            result: Optional[Dict[str, Any]] = None) -> None:
        result_json = json.dumps(result, ensure_ascii=False)[:32000] if result is not None else None
        with self._connect() as conn:
            conn.execute(
                "UPDATE ai_tool_confirmations SET status=?, result_json=? WHERE id=?",
                (status, result_json, confirmation_id),
            )

    def add_notification(self, kind: str, title: str, content: str, dedupe_key: str,
                         payload: Optional[Dict[str, Any]] = None) -> Optional[int]:
        with self._connect() as conn:
            cursor = conn.execute(
                "INSERT OR IGNORE INTO ai_notifications(kind,title,content,payload_json,dedupe_key,created_at) "
                "VALUES(?,?,?,?,?,?)",
                (kind, title, content, json.dumps(payload, ensure_ascii=False) if payload else None,
                 dedupe_key, utc_now()),
            )
            return int(cursor.lastrowid) if cursor.rowcount == 1 else None

    def list_notifications(self, after_id: int = 0, limit: int = 100) -> list[Dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT id,kind,title,content,created_at FROM ai_notifications "
                "WHERE id>? ORDER BY id ASC LIMIT ?", (max(int(after_id), 0), min(max(int(limit), 1), 200)),
            ).fetchall()
        return [dict(row) for row in rows]

    def queue_notification_delivery(self, notification_id: int, channel: str, target: str) -> None:
        now = utc_now()
        with self._connect() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO ai_notification_deliveries("
                "notification_id,channel,target,status,attempts,next_attempt_at,updated_at) "
                "VALUES(?,?,?,'pending',0,?,?)",
                (int(notification_id), str(channel), str(target), now, now),
            )

    def list_due_notification_deliveries(self, limit: int = 5) -> list[Dict[str, Any]]:
        bounded = max(1, min(int(limit), 20))
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT d.id,d.notification_id,d.channel,d.target,d.attempts,n.title,n.content "
                "FROM ai_notification_deliveries d JOIN ai_notifications n ON n.id=d.notification_id "
                "WHERE d.status IN ('pending','failed') AND d.attempts<5 AND d.next_attempt_at<=? "
                "ORDER BY d.id ASC LIMIT ?",
                (utc_now(), bounded),
            ).fetchall()
        return [dict(row) for row in rows]

    def finish_notification_delivery(self, delivery_id: int, success: bool,
                                     error: str = "") -> None:
        now = datetime.now(timezone.utc)
        with self._connect() as conn:
            row = conn.execute(
                "SELECT attempts FROM ai_notification_deliveries WHERE id=?", (int(delivery_id),)
            ).fetchone()
            if row is None:
                return
            attempts = int(row["attempts"] or 0) + 1
            if success:
                conn.execute(
                    "UPDATE ai_notification_deliveries SET status='sent',attempts=?,last_error=NULL,"
                    "sent_at=?,next_attempt_at=?,updated_at=? WHERE id=?",
                    (attempts, now.isoformat(timespec="seconds"), now.isoformat(timespec="seconds"),
                     now.isoformat(timespec="seconds"), int(delivery_id)),
                )
            else:
                delay_seconds = min(900, 60 * (2 ** max(0, attempts - 1)))
                next_attempt = now.timestamp() + delay_seconds
                next_text = datetime.fromtimestamp(next_attempt, timezone.utc).isoformat(timespec="seconds")
                conn.execute(
                    "UPDATE ai_notification_deliveries SET status='failed',attempts=?,last_error=?,"
                    "next_attempt_at=?,updated_at=? WHERE id=?",
                    (attempts, str(error)[:500], next_text, now.isoformat(timespec="seconds"), int(delivery_id)),
                )
