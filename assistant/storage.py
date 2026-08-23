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
