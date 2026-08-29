"""AI-specific SQLite tables. Kept separate from the document store schema."""

from __future__ import annotations

import json
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class AIStore:
    # Bounded growth for chat history, audit rows and notifications. Usage rows
    # are never pruned: they are the cumulative token audit trail and ~100
    # bytes each, so a personal hub stays in the low MBs for years.
    CONVERSATION_STORAGE_LIMIT_BYTES = 8 * 1024 * 1024
    PRUNE_MAX_AUDIT_ROWS = 1000
    PRUNE_MAX_NOTIFICATIONS = 500
    PRUNE_INTERVAL_SEC = 86_400

    def __init__(self, db_path: Path):
        self.db_path = Path(db_path)
        self._next_prune_monotonic = time.monotonic() + self.PRUNE_INTERVAL_SEC

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
                CREATE TABLE IF NOT EXISTS ai_provider_configs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL DEFAULT '', provider TEXT NOT NULL,
                    base_url TEXT NOT NULL, model TEXT NOT NULL,
                    api_key_ciphertext TEXT, enabled INTEGER NOT NULL DEFAULT 1,
                    model_quota_tokens INTEGER,
                    position INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL, updated_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_ai_provider_configs_order
                    ON ai_provider_configs(enabled,position,id);
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
            if "cache_hit_tokens" not in columns:
                conn.execute("ALTER TABLE ai_usage ADD COLUMN cache_hit_tokens INTEGER NOT NULL DEFAULT 0")
            if "cache_miss_tokens" not in columns:
                conn.execute("ALTER TABLE ai_usage ADD COLUMN cache_miss_tokens INTEGER NOT NULL DEFAULT 0")
            if "config_id" not in columns:
                conn.execute("ALTER TABLE ai_usage ADD COLUMN config_id INTEGER")
            config_columns = {row["name"] for row in conn.execute("PRAGMA table_info(ai_config)")}
            if "enabled" not in config_columns:
                conn.execute("ALTER TABLE ai_config ADD COLUMN enabled INTEGER NOT NULL DEFAULT 1")
            # One-time migration from the phase-one singleton.  The old table
            # remains readable for rollback, but is cleared after a successful
            # copy so deleting all new configs cannot resurrect it on restart.
            legacy = conn.execute("SELECT * FROM ai_config WHERE id=1").fetchone()
            if legacy is not None and conn.execute(
                "SELECT COUNT(*) AS c FROM ai_provider_configs"
            ).fetchone()["c"] == 0:
                now = utc_now()
                cursor = conn.execute(
                    "INSERT INTO ai_provider_configs(name,provider,base_url,model,api_key_ciphertext,enabled,"
                    "model_quota_tokens,position,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (str(legacy["model"] or legacy["provider"]), legacy["provider"], legacy["base_url"],
                     legacy["model"], legacy["api_key_ciphertext"], int(legacy["enabled"]),
                     None, 0, now, now),
                )
                conn.execute(
                    "UPDATE ai_usage SET config_id=? WHERE config_id IS NULL AND provider=? AND model=?",
                    (cursor.lastrowid, legacy["provider"], legacy["model"]),
                )
                conn.execute("DELETE FROM ai_config WHERE id=1")
        self._maybe_prune()

    def _maybe_prune(self) -> None:
        now = time.monotonic()
        if now < self._next_prune_monotonic:
            return
        self._next_prune_monotonic = now + self.PRUNE_INTERVAL_SEC
        try:
            self.prune_history()
        except sqlite3.Error:
            pass

    def prune_history(self, *, max_audit_rows: int = PRUNE_MAX_AUDIT_ROWS,
                      max_notifications: int = PRUNE_MAX_NOTIFICATIONS) -> Dict[str, int]:
        """Bound auxiliary tables without imposing a conversation count or age limit."""
        deleted: Dict[str, int] = {}
        with self._connect() as conn:
            for table, keep in (("ai_tool_audit", max_audit_rows), ("ai_notifications", max_notifications)):
                row = conn.execute(
                    f"SELECT MIN(id) AS cutoff FROM (SELECT id FROM {table} ORDER BY id DESC LIMIT ?)",
                    (max(0, int(keep)),),
                ).fetchone()
                cutoff_id = row["cutoff"] if row else None
                if cutoff_id is not None:
                    deleted[table] = conn.execute(
                        f"DELETE FROM {table} WHERE id < ?", (cutoff_id,),
                    ).rowcount
            deleted["expired_confirmations"] = conn.execute(
                "DELETE FROM ai_tool_confirmations WHERE status IN ('pending','executing') AND expires_at < ?",
                (utc_now(),),
            ).rowcount
        deleted.update(self.enforce_conversation_storage())
        return deleted

    def enforce_conversation_storage(self, *, limit_bytes: int = CONVERSATION_STORAGE_LIMIT_BYTES,
                                     protected_conversation_id: Optional[str] = None) -> Dict[str, int]:
        """Keep all conversation content within a UTF-8 byte budget.

        Old whole conversations are removed first. If the protected/current
        conversation alone exceeds the budget, only its oldest messages are
        trimmed while its newest two messages are retained.
        """
        limit = max(0, int(limit_bytes))
        deleted_conversations = 0
        deleted_messages = 0
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                def stored_bytes() -> int:
                    row = conn.execute(
                        "SELECT COALESCE(SUM(LENGTH(CAST(content AS BLOB))),0) AS bytes FROM messages"
                    ).fetchone()
                    return int(row["bytes"] or 0)

                while stored_bytes() > limit:
                    if protected_conversation_id:
                        row = conn.execute(
                            "SELECT id FROM conversations WHERE id<>? ORDER BY updated_at ASC, created_at ASC LIMIT 1",
                            (protected_conversation_id,),
                        ).fetchone()
                    else:
                        row = conn.execute(
                            "SELECT id FROM conversations ORDER BY updated_at ASC, created_at ASC LIMIT 1"
                        ).fetchone()
                    if row is None:
                        break
                    deleted_conversations += conn.execute(
                        "DELETE FROM conversations WHERE id=?", (row["id"],),
                    ).rowcount

                if stored_bytes() > limit and protected_conversation_id:
                    while stored_bytes() > limit:
                        row = conn.execute(
                            "SELECT id FROM messages WHERE conversation_id=? "
                            "AND id NOT IN (SELECT id FROM messages WHERE conversation_id=? ORDER BY id DESC LIMIT 2) "
                            "ORDER BY id ASC LIMIT 1",
                            (protected_conversation_id, protected_conversation_id),
                        ).fetchone()
                        if row is None:
                            break
                        deleted_messages += conn.execute("DELETE FROM messages WHERE id=?", (row["id"],)).rowcount
                conn.execute("COMMIT")
            except Exception:
                conn.execute("ROLLBACK")
                raise
        return {"storage_conversations": deleted_conversations, "storage_messages": deleted_messages}

    def list_configs(self, *, enabled_only: bool = False) -> List[Dict[str, Any]]:
        where = "WHERE enabled=1" if enabled_only else ""
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM ai_provider_configs {where} ORDER BY position ASC,id ASC"
            ).fetchall()
        return [dict(row) for row in rows]

    def get_config(self, config_id: Optional[int] = None) -> Optional[Dict[str, Any]]:
        with self._connect() as conn:
            if config_id is None:
                row = conn.execute(
                    "SELECT * FROM ai_provider_configs ORDER BY position ASC,id ASC LIMIT 1"
                ).fetchone()
            else:
                row = conn.execute(
                    "SELECT * FROM ai_provider_configs WHERE id=?", (int(config_id),)
                ).fetchone()
        return dict(row) if row else None

    def create_config(self, name: str, provider: str, base_url: str, model: str,
                      ciphertext: str, enabled: bool, model_quota_tokens: Optional[int] = None,
                      position: Optional[int] = None) -> Dict[str, Any]:
        now = utc_now()
        with self._connect() as conn:
            if position is None:
                row = conn.execute(
                    "SELECT COALESCE(MAX(position),-1)+1 AS next_position FROM ai_provider_configs"
                ).fetchone()
                position = int(row["next_position"])
            cursor = conn.execute(
                "INSERT INTO ai_provider_configs(name,provider,base_url,model,api_key_ciphertext,enabled,"
                "model_quota_tokens,position,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                (name, provider, base_url, model, ciphertext, int(enabled), model_quota_tokens,
                 int(position), now, now),
            )
        return self.get_config(int(cursor.lastrowid)) or {}

    def update_config(self, config_id: int, *, name: str, provider: str, base_url: str,
                      model: str, ciphertext: str, enabled: bool,
                      model_quota_tokens: Optional[int], position: int) -> Optional[Dict[str, Any]]:
        with self._connect() as conn:
            updated = conn.execute(
                "UPDATE ai_provider_configs SET name=?,provider=?,base_url=?,model=?,api_key_ciphertext=?,"
                "enabled=?,model_quota_tokens=?,position=?,updated_at=? WHERE id=?",
                (name, provider, base_url, model, ciphertext, int(enabled), model_quota_tokens,
                 int(position), utc_now(), int(config_id)),
            ).rowcount
        return self.get_config(config_id) if updated else None

    def save_config(self, provider: str, base_url: str, model: str, ciphertext: str, enabled: bool,
                    model_quota_tokens: Optional[int] = None, name: Optional[str] = None) -> None:
        """Compatibility wrapper for phase-one callers of the singleton store API."""
        current = self.get_config()
        if current:
            self.update_config(
                current["id"], name=str(name or current["name"] or model), provider=provider,
                base_url=base_url, model=model, ciphertext=ciphertext, enabled=enabled,
                model_quota_tokens=model_quota_tokens, position=int(current["position"]),
            )
        else:
            self.create_config(str(name or model), provider, base_url, model, ciphertext,
                               enabled, model_quota_tokens)

    def delete_config(self, config_id: Optional[int] = None) -> bool:
        current = self.get_config() if config_id is None else None
        target_id = int(config_id if config_id is not None else current["id"]) if (config_id is not None or current) else None
        if target_id is None:
            return False
        with self._connect() as conn:
            return bool(conn.execute("DELETE FROM ai_provider_configs WHERE id=?", (target_id,)).rowcount)

    def create_conversation(self, conversation_id: str, title: Optional[str] = None) -> None:
        now = utc_now()
        clean_title = str(title).strip()[:32] if title is not None else ""
        with self._connect() as conn:
            conn.execute("INSERT OR IGNORE INTO conversations(id,title,created_at,updated_at) VALUES(?,?,?,?)",
                         (conversation_id, clean_title or "新对话", now, now))

    def rename_conversation(self, conversation_id: str, title: str) -> Optional[Dict[str, Any]]:
        clean_title = str(title or "").strip()
        if not clean_title or len(clean_title) > 64:
            raise ValueError("title must contain 1 to 64 characters")
        with self._connect() as conn:
            updated = conn.execute(
                "UPDATE conversations SET title=?,updated_at=? WHERE id=?",
                (clean_title, utc_now(), conversation_id),
            ).rowcount
            row = conn.execute(
                "SELECT id,title,created_at,updated_at FROM conversations WHERE id=?",
                (conversation_id,),
            ).fetchone() if updated else None
        return dict(row) if row else None

    def list_conversations(self, limit: Optional[int] = None) -> list[Dict[str, Any]]:
        sql = "SELECT id, COALESCE(NULLIF(TRIM(title),''),'新对话') AS title, created_at, updated_at FROM conversations ORDER BY updated_at DESC"
        params: tuple[Any, ...] = ()
        if limit is not None:
            sql += " LIMIT ?"
            params = (max(1, int(limit)),)
        with self._connect() as conn:
            rows = conn.execute(sql, params).fetchall()
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
        self.enforce_conversation_storage(protected_conversation_id=conversation_id)

    def replace_messages(self, conversation_id: str, messages: List[Dict[str, str]]) -> None:
        """Make stored history match exactly what the client sent.

        The APP replays the visible history on every turn; re-inserting it
        verbatim duplicates rows on every request, so each send replaces the
        conversation's stored history in one transaction."""
        now = utc_now()
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                conn.execute("DELETE FROM messages WHERE conversation_id=?", (conversation_id,))
                conn.executemany(
                    "INSERT INTO messages(conversation_id,role,content,created_at) VALUES(?,?,?,?)",
                    [(conversation_id, str(m["role"]), str(m["content"]), now) for m in messages],
                )
                conn.execute("UPDATE conversations SET updated_at=? WHERE id=?", (now, conversation_id))
                conn.execute("COMMIT")
            except Exception:
                conn.execute("ROLLBACK")
                raise
        self.enforce_conversation_storage(protected_conversation_id=conversation_id)

    def add_usage(self, conversation_id: str, provider: str, model: str, usage: Dict[str, Any],
                  status: str = "completed", config_id: Optional[int] = None) -> None:
        with self._connect() as conn:
            conn.execute("""INSERT INTO ai_usage(conversation_id,provider,model,prompt_tokens,completion_tokens,total_tokens,status,usage_known,usage_json,cache_hit_tokens,cache_miss_tokens,created_at,config_id)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""", (conversation_id, provider, model,
                int(usage.get("prompt_tokens") or 0), int(usage.get("completion_tokens") or 0),
                int(usage.get("total_tokens") or 0), status, int(bool(usage)),
                json.dumps(usage, separators=(",", ":")) if usage else None,
                int(usage.get("cache_hit_tokens") or 0), int(usage.get("cache_miss_tokens") or 0),
                utc_now(), config_id))
        self._maybe_prune()

    def usage_daily(self, days: int = 14) -> List[Dict[str, Any]]:
        """Per-Beijing-day token totals for the usage trend chart (oldest first)."""
        bounded = max(1, min(int(days), 60))
        window = (f'-{bounded} days',)
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT date(datetime(created_at, '+8 hours')) AS day,"
                " COUNT(*) AS requests,"
                " COALESCE(SUM(prompt_tokens),0) AS prompt_tokens,"
                " COALESCE(SUM(completion_tokens),0) AS completion_tokens,"
                " COALESCE(SUM(total_tokens),0) AS total_tokens,"
                " COALESCE(SUM(cache_hit_tokens),0) AS cache_hit_tokens,"
                " COALESCE(SUM(cache_miss_tokens),0) AS cache_miss_tokens"
                " FROM ai_usage"
                " WHERE created_at >= datetime('now', ?, '-8 hours')"
                " GROUP BY day ORDER BY day", window,
            ).fetchall()
            models = conn.execute(
                "SELECT date(datetime(created_at, '+8 hours')) AS day, model,"
                " COALESCE(SUM(total_tokens),0) AS total_tokens"
                " FROM ai_usage"
                " WHERE created_at >= datetime('now', ?, '-8 hours')"
                " GROUP BY day, model", window,
            ).fetchall()
        model_map: Dict[str, Dict[str, int]] = {}
        for row in models:
            model_map.setdefault(row["day"], {})[row["model"]] = int(row["total_tokens"])
        return [{
            "date": row["day"],
            "requests": int(row["requests"]),
            "prompt_tokens": int(row["prompt_tokens"]),
            "completion_tokens": int(row["completion_tokens"]),
            "total_tokens": int(row["total_tokens"]),
            "cache_hit_tokens": int(row["cache_hit_tokens"]),
            "cache_miss_tokens": int(row["cache_miss_tokens"]),
            "models": model_map.get(row["day"], {}),
        } for row in rows]

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

    @staticmethod
    def _quota_view(total_tokens: int, quota: Optional[int]) -> Dict[str, Any]:
        if quota is None:
            return {
                "token_quota": None, "quota_status": "unknown",
                "used_percent": None, "remaining_percent": None,
            }
        quota_value = int(quota)
        ratio = (float(total_tokens) / quota_value * 100.0) if quota_value > 0 else 100.0
        used_percent = round(min(max(ratio, 0.0), 100.0), 2)
        return {
            "token_quota": quota_value, "quota_status": "known",
            "used_percent": used_percent,
            "remaining_percent": round(max(0.0, 100.0 - used_percent), 2),
        }

    def usage_by_config(self) -> List[Dict[str, Any]]:
        """Cumulative token usage for every configured API record."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT c.id AS config_id,c.name,c.provider,c.model,c.model_quota_tokens,"
                "COALESCE(SUM(u.prompt_tokens),0) AS prompt_tokens,"
                "COALESCE(SUM(u.completion_tokens),0) AS completion_tokens,"
                "COALESCE(SUM(u.total_tokens),0) AS total_tokens "
                "FROM ai_provider_configs c LEFT JOIN ai_usage u ON u.config_id=c.id "
                "GROUP BY c.id,c.name,c.provider,c.model,c.model_quota_tokens "
                "ORDER BY c.position ASC,c.id ASC"
            ).fetchall()
        result: List[Dict[str, Any]] = []
        for row in rows:
            item = {
                "config_id": int(row["config_id"]), "name": row["name"],
                "provider": row["provider"], "model": row["model"],
                "prompt_tokens": int(row["prompt_tokens"] or 0),
                "completion_tokens": int(row["completion_tokens"] or 0),
                "total_tokens": int(row["total_tokens"] or 0),
            }
            item.update(self._quota_view(item["total_tokens"], row["model_quota_tokens"]))
            result.append(item)
        return result

    def usage_by_model(self) -> List[Dict[str, Any]]:
        """Cumulative usage grouped by provider/model across API records."""
        with self._connect() as conn:
            usage_rows = conn.execute(
                "SELECT provider,model,COALESCE(SUM(prompt_tokens),0) AS prompt_tokens,"
                "COALESCE(SUM(completion_tokens),0) AS completion_tokens,"
                "COALESCE(SUM(total_tokens),0) AS total_tokens "
                "FROM ai_usage GROUP BY provider,model ORDER BY total_tokens DESC,provider,model"
            ).fetchall()
            config_rows = conn.execute(
                "SELECT provider,model,model_quota_tokens FROM ai_provider_configs"
            ).fetchall()
        usage = {(row["provider"], row["model"]): row for row in usage_rows}
        configs: Dict[tuple[str, str], List[Optional[int]]] = {}
        for row in config_rows:
            configs.setdefault((row["provider"], row["model"]), []).append(row["model_quota_tokens"])
        result: List[Dict[str, Any]] = []
        for provider, model in sorted(set(usage) | set(configs)):
            row = usage.get((provider, model))
            total_tokens = int(row["total_tokens"] or 0) if row else 0
            quotas = configs.get((provider, model), [])
            quota = sum(int(value) for value in quotas) if quotas and all(value is not None for value in quotas) else None
            item = {
                "provider": provider, "model": model,
                "prompt_tokens": int(row["prompt_tokens"] or 0) if row else 0,
                "completion_tokens": int(row["completion_tokens"] or 0) if row else 0,
                "total_tokens": total_tokens,
            }
            item.update(self._quota_view(total_tokens, quota))
            result.append(item)
        result.sort(key=lambda item: (-item["total_tokens"], item["provider"], item["model"]))
        return result

    def conversation_storage(self) -> Dict[str, int]:
        """How much space the stored AI conversations occupy."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT COUNT(DISTINCT conversation_id) AS conversations, COUNT(*) AS messages,"
                " COALESCE(SUM(LENGTH(CAST(content AS BLOB))),0) AS bytes FROM messages"
            ).fetchone()
        return {
            "conversations": int(row["conversations"] or 0),
            "messages": int(row["messages"] or 0),
            "bytes": int(row["bytes"] or 0),
        }

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

    def complete_client_confirmation(self, confirmation_id: str, status: str,
                                     result: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
        """Atomically finish an APP-executed confirmation exactly once."""
        if status not in {"completed", "failed"}:
            raise ValueError("invalid client confirmation status")
        result_json = json.dumps(result, ensure_ascii=False)[:32000] if result is not None else None
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT * FROM ai_tool_confirmations WHERE id=? AND status='executing' AND expires_at>=?",
                (confirmation_id, utc_now()),
            ).fetchone()
            if row is None:
                conn.execute("ROLLBACK")
                return None
            preview = json.loads(row["preview_json"])
            if preview.get("executor") != "app":
                conn.execute("ROLLBACK")
                return None
            changed = conn.execute(
                "UPDATE ai_tool_confirmations SET status=?, result_json=? WHERE id=? AND status='executing'",
                (status, result_json, confirmation_id),
            ).rowcount
            if changed != 1:
                conn.execute("ROLLBACK")
                return None
            conn.execute("COMMIT")
        result_row = dict(row)
        result_row["arguments"] = json.loads(result_row.pop("arguments_json"))
        result_row["preview"] = preview
        return result_row

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
