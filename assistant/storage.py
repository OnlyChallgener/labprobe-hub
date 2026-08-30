"""AI-specific SQLite tables. Kept separate from the document store schema."""

from __future__ import annotations

import json
import sqlite3
import time
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional


_UNSET = object()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def usage_known(usage: Dict[str, Any]) -> bool:
    """A usage frame counts as known only when it reports positive tokens;
    some providers stream all-zero frames which would fake the usage page."""
    return any(
        isinstance(value, (int, float)) and not isinstance(value, bool) and value > 0
        for value in usage.values()
    )


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

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(str(self.db_path), timeout=15, isolation_level=None)
        try:
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys=ON")
            conn.execute("PRAGMA busy_timeout=15000")
            yield conn
        finally:
            conn.close()

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
                    usage_record_hidden INTEGER NOT NULL DEFAULT 0,
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
                    confirmed_at TEXT, result_json TEXT, conversation_id TEXT
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
            if "cache_reported_input_tokens" not in columns:
                conn.execute(
                    "ALTER TABLE ai_usage ADD COLUMN cache_reported_input_tokens INTEGER NOT NULL DEFAULT 0"
                )
                conn.execute(
                    "UPDATE ai_usage SET cache_reported_input_tokens="
                    "COALESCE(cache_hit_tokens,0)+COALESCE(cache_miss_tokens,0)"
                )
            if "config_id" not in columns:
                conn.execute("ALTER TABLE ai_usage ADD COLUMN config_id INTEGER")
            config_columns = {row["name"] for row in conn.execute("PRAGMA table_info(ai_config)")}
            if "enabled" not in config_columns:
                conn.execute("ALTER TABLE ai_config ADD COLUMN enabled INTEGER NOT NULL DEFAULT 1")
            provider_config_columns = {
                row["name"] for row in conn.execute("PRAGMA table_info(ai_provider_configs)")
            }
            if "manual_total_tokens" not in provider_config_columns:
                conn.execute("ALTER TABLE ai_provider_configs ADD COLUMN manual_total_tokens INTEGER")
            if "manual_calibrated_at" not in provider_config_columns:
                conn.execute("ALTER TABLE ai_provider_configs ADD COLUMN manual_calibrated_at TEXT")
            if "manual_usage_floor_id" not in provider_config_columns:
                conn.execute("ALTER TABLE ai_provider_configs ADD COLUMN manual_usage_floor_id INTEGER")
            if "usage_record_hidden" not in provider_config_columns:
                conn.execute(
                    "ALTER TABLE ai_provider_configs ADD COLUMN usage_record_hidden INTEGER NOT NULL DEFAULT 0"
                )
            confirmation_columns = {
                row["name"] for row in conn.execute("PRAGMA table_info(ai_tool_confirmations)")
            }
            if "conversation_id" not in confirmation_columns:
                conn.execute("ALTER TABLE ai_tool_confirmations ADD COLUMN conversation_id TEXT")
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
        self._reattribute_usage_config_ids()
        self._maybe_prune()

    def _reattribute_usage_config_ids(self) -> None:
        """Null out usage rows whose config no longer exists, then backfill.

        Deleting and re-creating an API config leaves old usage rows pointing
        at the removed id; the per-config quota card would silently exclude
        them while per-model totals still count them. Re-nullifying orphans
        before the pair/model backfill lets them attach to the current config.
        """
        with self._connect() as conn:
            conn.execute(
                "UPDATE ai_usage SET config_id=NULL WHERE config_id IS NOT NULL "
                "AND config_id NOT IN (SELECT id FROM ai_provider_configs)"
            )
        self._backfill_usage_config_ids()

    def _backfill_usage_config_ids(self) -> None:
        """Attribute pre-multi-config usage rows to their matching API config.

        Per-model totals cover every usage row, while per-config quota rows only
        counted rows that already carried a config_id; without this backfill the
        two cards on the usage page disagree for accounts used before the
        config was created. Matching prefers the same provider+model pair and
        falls back to the first config with the same model (position order).
        """
        with self._connect() as conn:
            configs = conn.execute(
                "SELECT id, provider, model FROM ai_provider_configs ORDER BY position ASC, id ASC"
            ).fetchall()
            if not configs:
                return
            by_pair: Dict[tuple[str, str], int] = {}
            by_model: Dict[str, int] = {}
            for row in configs:
                by_pair.setdefault((str(row["provider"]), str(row["model"])), int(row["id"]))
                by_model.setdefault(str(row["model"]), int(row["id"]))
            unattributed = conn.execute(
                "SELECT provider, model FROM ai_usage WHERE config_id IS NULL GROUP BY provider, model"
            ).fetchall()
            for row in unattributed:
                provider, model = str(row["provider"]), str(row["model"])
                config_id = by_pair.get((provider, model)) or by_model.get(model)
                if config_id is None:
                    continue
                conn.execute(
                    "UPDATE ai_usage SET config_id=? WHERE config_id IS NULL AND provider=? AND model=?",
                    (config_id, provider, model),
                )

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
            current = conn.execute(
                "SELECT model FROM ai_provider_configs WHERE id=?", (int(config_id),)
            ).fetchone()
            model_changed = current is not None and str(current["model"]) != str(model)
            if model_changed:
                # Calibration belongs to the old model, not to the API key or
                # endpoint. Preserve the provider config but start the new
                # model with an independent cumulative baseline.
                updated = conn.execute(
                    "UPDATE ai_provider_configs SET name=?,provider=?,base_url=?,model=?,api_key_ciphertext=?,"
                    "enabled=?,model_quota_tokens=?,manual_total_tokens=NULL,manual_calibrated_at=NULL,"
                    "manual_usage_floor_id=NULL,usage_record_hidden=0,position=?,updated_at=? WHERE id=?",
                    (name, provider, base_url, model, ciphertext, int(enabled), model_quota_tokens,
                     int(position), utc_now(), int(config_id)),
                ).rowcount
            else:
                updated = conn.execute(
                    "UPDATE ai_provider_configs SET name=?,provider=?,base_url=?,model=?,api_key_ciphertext=?,"
                    "enabled=?,model_quota_tokens=?,usage_record_hidden=CASE WHEN ? IS NOT NULL THEN 0 ELSE usage_record_hidden END,"
                    "position=?,updated_at=? WHERE id=?",
                    (name, provider, base_url, model, ciphertext, int(enabled), model_quota_tokens, model_quota_tokens,
                     int(position), utc_now(), int(config_id)),
                ).rowcount
        return self.get_config(config_id) if updated else None

    def migrate_config_ciphertext(self, config_id: int, old_ciphertext: str,
                                  new_ciphertext: str) -> bool:
        """Persist a rotated-key ciphertext only if it has not changed meanwhile."""
        with self._connect() as conn:
            return bool(conn.execute(
                "UPDATE ai_provider_configs SET api_key_ciphertext=?,updated_at=? "
                "WHERE id=? AND api_key_ciphertext=?",
                (new_ciphertext, utc_now(), int(config_id), old_ciphertext),
            ).rowcount)

    def migrate_config_base_url(self, config_id: int, old_base_url: str,
                                new_base_url: str) -> bool:
        """Canonicalize a legacy provider URL with a compare-and-swap update."""
        with self._connect() as conn:
            return bool(conn.execute(
                "UPDATE ai_provider_configs SET base_url=?,updated_at=? "
                "WHERE id=? AND base_url=?",
                (new_base_url, utc_now(), int(config_id), old_base_url),
            ).rowcount)

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
            deleted = bool(conn.execute("DELETE FROM ai_provider_configs WHERE id=?", (target_id,)).rowcount)
        if deleted:
            # Re-attach the deleted config's usage rows to any remaining
            # config with the same provider/model so quota cards stay truthful.
            self._reattribute_usage_config_ids()
        return deleted

    def create_conversation(self, conversation_id: str, title: Optional[str] = None) -> None:
        now = utc_now()
        clean_title = str(title).strip()[:32] if title is not None else ""
        with self._connect() as conn:
            conn.execute("INSERT OR IGNORE INTO conversations(id,title,created_at,updated_at) VALUES(?,?,?,?)",
                         (conversation_id, clean_title or "新对话", now, now))

    def delete_conversation(self, conversation_id: str) -> bool:
        clean_id = str(conversation_id or "").strip()
        if not clean_id:
            return False
        with self._connect() as conn:
            conn.execute("BEGIN")
            try:
                conn.execute("DELETE FROM messages WHERE conversation_id=?", (clean_id,))
                deleted = conn.execute(
                    "DELETE FROM conversations WHERE id=?", (clean_id,),
                ).rowcount
                conn.execute("COMMIT")
            except Exception:
                conn.execute("ROLLBACK")
                raise
        self.enforce_conversation_storage()
        return bool(deleted)

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
                "SELECT id, role, content, created_at FROM messages "
                "WHERE conversation_id=? ORDER BY id DESC LIMIT ?",
                (conversation_id, int(limit)),
            ).fetchall()
        return [dict(row) for row in reversed(rows)]

    def add_message(self, conversation_id: str, role: str, content: str) -> int:
        with self._connect() as conn:
            cursor = conn.execute("INSERT INTO messages(conversation_id,role,content,created_at) VALUES(?,?,?,?)",
                                  (conversation_id, role, content, utc_now()))
            message_id = int(cursor.lastrowid)
            conn.execute("UPDATE conversations SET updated_at=? WHERE id=?", (utc_now(), conversation_id))
        self.enforce_conversation_storage(protected_conversation_id=conversation_id)
        return message_id

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
                  status: str = "completed", config_id: Optional[int] = None,
                  error: Optional[str] = None) -> None:
        payload = dict(usage) if usage else {}
        cache_hit = int(usage.get("cache_hit_tokens") or 0)
        cache_miss = int(usage.get("cache_miss_tokens") or 0)
        cache_reported = usage.get("cache_reported_input_tokens")
        if cache_reported is None and (
            "cache_hit_tokens" in usage or "cache_miss_tokens" in usage
        ):
            # Legacy callers supplied the two cache buckets before explicit
            # coverage existed. Preserve their complete reported denominator.
            cache_reported = cache_hit + cache_miss
        if error:
            payload["error"] = str(error)[:300]
        with self._connect() as conn:
            conn.execute("""INSERT INTO ai_usage(conversation_id,provider,model,prompt_tokens,completion_tokens,total_tokens,status,usage_known,usage_json,cache_hit_tokens,cache_miss_tokens,cache_reported_input_tokens,created_at,config_id)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", (conversation_id, provider, model,
                int(usage.get("prompt_tokens") or 0), int(usage.get("completion_tokens") or 0),
                int(usage.get("total_tokens") or 0), status, int(usage_known(usage)),
                json.dumps(payload, separators=(",", ":"), ensure_ascii=False) if payload else None,
                cache_hit, cache_miss, int(cache_reported or 0), utc_now(), config_id))
        self._maybe_prune()

    @staticmethod
    def _effective_config_total(config: sqlite3.Row | Dict[str, Any], usage_rows: List[sqlite3.Row]) -> int:
        """Return the displayed total for one config.

        A manual calibration is a durable baseline, not a signed usage row.
        Only task rows created after the calibration floor are added to it;
        task history remains intact and deleting a conversation cannot alter
        the calibrated baseline.
        """
        config_id = int(config["id"])
        model = str(config["model"])
        baseline = config.get("manual_total_tokens") if isinstance(config, dict) else config["manual_total_tokens"]
        scoped = [
            row for row in usage_rows
            if int(row["config_id"] or 0) == config_id
            and str(row["model"]) == model
        ]
        if baseline is None:
            return sum(int(row["total_tokens"] or 0) for row in scoped)
        floor = int((config.get("manual_usage_floor_id") if isinstance(config, dict) else config["manual_usage_floor_id"]) or 0)
        return int(baseline) + sum(
            int(row["total_tokens"] or 0)
            for row in scoped
            if str(row["status"] or "") != "adjusted" and int(row["id"]) > floor
        )

    @staticmethod
    def _effective_rows_for_config(config: sqlite3.Row | Dict[str, Any], usage_rows: List[sqlite3.Row]) -> List[sqlite3.Row]:
        config_id = int(config["id"])
        model = str(config["model"])
        scoped = [
            row for row in usage_rows
            if int(row["config_id"] or 0) == config_id
            and str(row["model"]) == model
        ]
        baseline = config.get("manual_total_tokens") if isinstance(config, dict) else config["manual_total_tokens"]
        if baseline is None:
            return scoped
        floor = int((config.get("manual_usage_floor_id") if isinstance(config, dict) else config["manual_usage_floor_id"]) or 0)
        return [row for row in scoped if str(row["status"] or "") != "adjusted" and int(row["id"]) > floor]

    def _usage_context(self) -> tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        with self._connect() as conn:
            configs = [dict(row) for row in conn.execute(
                "SELECT * FROM ai_provider_configs ORDER BY position ASC,id ASC"
            ).fetchall()]
            usage_rows = [dict(row) for row in conn.execute("SELECT * FROM ai_usage").fetchall()]
        return configs, usage_rows

    def usage_daily(self, days: int = 14) -> List[Dict[str, Any]]:
        """Per-Beijing-day token totals for the usage trend chart (oldest first)."""
        bounded = max(1, min(int(days), 60))
        _configs, usage_rows = self._usage_context()
        beijing = timezone(timedelta(hours=8))
        first_day = datetime.now(timezone.utc).astimezone(beijing).date() - timedelta(days=bounded - 1)
        def day_for(value: Any) -> str:
            try:
                parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
                if parsed.tzinfo is None:
                    parsed = parsed.replace(tzinfo=timezone.utc)
                return parsed.astimezone(beijing).date().isoformat()
            except (TypeError, ValueError):
                return str(value or "")[:10]
        def in_window(row: Dict[str, Any]) -> bool:
            try:
                return datetime.fromisoformat(day_for(row["created_at"])).date() >= first_day
            except (TypeError, ValueError, OverflowError):
                return False
        result: Dict[str, Dict[str, Any]] = {}
        model_map: Dict[str, Dict[str, int]] = {}
        for row in usage_rows:
            if not in_window(row):
                continue
            day = day_for(row["created_at"])
            item = result.setdefault(day, {"date": day, "requests": 0, "prompt_tokens": 0,
                                           "completion_tokens": 0, "total_tokens": 0,
                                           "cache_hit_tokens": 0, "cache_miss_tokens": 0,
                                           "cache_reported_input_tokens": 0})
            if str(row.get("status") or "") != "adjusted":
                item["requests"] += 1
            item["prompt_tokens"] += int(row.get("prompt_tokens") or 0)
            item["completion_tokens"] += int(row.get("completion_tokens") or 0)
            item["total_tokens"] += int(row.get("total_tokens") or 0)
            item["cache_hit_tokens"] += int(row.get("cache_hit_tokens") or 0)
            item["cache_miss_tokens"] += int(row.get("cache_miss_tokens") or 0)
            item["cache_reported_input_tokens"] += int(row.get("cache_reported_input_tokens") or 0)
            model_map.setdefault(day, {})[row["model"]] = (
                model_map.setdefault(day, {}).get(row["model"], 0) + int(row.get("total_tokens") or 0)
            )
        # Daily charts are an aggregation of immutable task records. Manual
        # cumulative calibration belongs only to the headline/quota baseline;
        # injecting it into its save date created a fake spike and made the
        # displayed input/output decomposition impossible to reconcile.
        for day, item in result.items():
            item["models"] = model_map.get(day, {})
        return [result[day] for day in sorted(result)]

    def usage_summary(self) -> Dict[str, int]:
        configs, usage_rows = self._usage_context()
        config_ids = {int(config["id"]) for config in configs}
        configs_by_id = {int(config["id"]): config for config in configs}
        result = {"requests": 0, "prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}
        today = {"requests": 0, "total_tokens": 0}
        beijing = timezone(timedelta(hours=8))
        today_key = datetime.now(timezone.utc).astimezone(beijing).date().isoformat()
        def row_day(value: Any) -> str:
            try:
                parsed = datetime.fromisoformat(str(value or "").replace("Z", "+00:00"))
                if parsed.tzinfo is None:
                    parsed = parsed.replace(tzinfo=timezone.utc)
                return parsed.astimezone(beijing).date().isoformat()
            except (TypeError, ValueError):
                return str(value or "")[:10]
        for row in usage_rows:
            if str(row.get("status") or "") != "adjusted":
                result["requests"] += 1
                if row_day(row.get("created_at")) == today_key:
                    today["requests"] += 1
            result["prompt_tokens"] += int(row.get("prompt_tokens") or 0)
            result["completion_tokens"] += int(row.get("completion_tokens") or 0)
        for config in configs:
            config_rows = [
                row for row in usage_rows
                if int(row.get("config_id") or 0) == int(config["id"])
                and str(row.get("model")) == str(config["model"])
            ]
            result["total_tokens"] += self._effective_config_total(config, config_rows)
        result["total_tokens"] += sum(
            int(row.get("total_tokens") or 0) for row in usage_rows
            if (
                not row.get("config_id") or int(row.get("config_id")) not in config_ids
                or str(row.get("model")) != str(configs_by_id[int(row["config_id"])]["model"])
            )
        )
        # "Today" is a task-period metric. Manual cumulative calibration is
        # authoritative for the all-time headline/quota only; it is not a task
        # and must never inflate the day on which the user saved it.
        today["total_tokens"] = sum(
            int(row.get("total_tokens") or 0) for row in usage_rows
            if str(row.get("status") or "") != "adjusted"
            and row_day(row.get("created_at")) == today_key
        )
        result["today_requests"] = today["requests"]
        result["today_total_tokens"] = today["total_tokens"]
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
        configs, usage_rows = self._usage_context()
        result: List[Dict[str, Any]] = []
        for row in configs:
            if bool(row.get("usage_record_hidden")):
                continue
            config_rows = [
                usage for usage in usage_rows
                if int(usage.get("config_id") or 0) == int(row["id"])
                and str(usage.get("model")) == str(row["model"])
            ]
            item = {
                "config_id": int(row["id"]), "name": row["name"],
                "provider": row["provider"], "model": row["model"],
                "prompt_tokens": sum(int(usage.get("prompt_tokens") or 0) for usage in config_rows),
                "completion_tokens": sum(int(usage.get("completion_tokens") or 0) for usage in config_rows),
                "total_tokens": self._effective_config_total(row, config_rows),
            }
            item.update(self._quota_view(item["total_tokens"], row.get("model_quota_tokens")))
            result.append(item)
        return result

    def usage_by_model(self) -> List[Dict[str, Any]]:
        """Cumulative usage grouped by provider/model across API records."""
        configs, usage_rows = self._usage_context()
        usage: Dict[tuple[str, str], Dict[str, int]] = {}
        for row in usage_rows:
            key = (row["provider"], row["model"])
            item = usage.setdefault(key, {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0})
            item["prompt_tokens"] += int(row.get("prompt_tokens") or 0)
            item["completion_tokens"] += int(row.get("completion_tokens") or 0)
        for config in configs:
            key = (config["provider"], config["model"])
            config_rows = [
                row for row in usage_rows
                if int(row.get("config_id") or 0) == int(config["id"])
                and str(row.get("model")) == str(config["model"])
            ]
            usage.setdefault(key, {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0})["total_tokens"] += self._effective_config_total(config, config_rows)
        configs_by_id = {int(config["id"]): config for config in configs}
        for row in usage_rows:
            config = configs_by_id.get(int(row.get("config_id") or 0))
            if config is not None and str(row.get("model")) == str(config["model"]):
                continue
            key = (row["provider"], row["model"])
            usage.setdefault(key, {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0})["total_tokens"] += int(row.get("total_tokens") or 0)
        config_quotas: Dict[tuple[str, str], List[Optional[int]]] = {}
        for row in configs:
            if bool(row.get("usage_record_hidden")):
                continue
            config_quotas.setdefault((row["provider"], row["model"]), []).append(row.get("model_quota_tokens"))
        result: List[Dict[str, Any]] = []
        for provider, model in sorted(set(usage) | set(config_quotas)):
            row = usage.get((provider, model))
            total_tokens = int(row.get("total_tokens") or 0) if row else 0
            quotas = config_quotas.get((provider, model), [])
            quota = sum(int(value) for value in quotas) if quotas and all(value is not None for value in quotas) else None
            item = {
                "provider": provider, "model": model,
                "prompt_tokens": int(row.get("prompt_tokens") or 0) if row else 0,
                "completion_tokens": int(row.get("completion_tokens") or 0) if row else 0,
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
                f"SELECT {fields} FROM ai_usage WHERE status<>'adjusted' ORDER BY id DESC LIMIT ?",
                (bounded_limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def usage_for_date(self, day: str) -> Dict[str, int]:
        """Return usage for an Asia/Shanghai calendar date without exposing secrets."""
        safe_day = str(day or "").strip()
        _configs, usage_rows = self._usage_context()
        result = {"requests": 0, "prompt_tokens": 0, "completion_tokens": 0,
                  "total_tokens": 0, "unknown_usage_requests": 0}
        beijing = timezone(timedelta(hours=8))
        def row_day(value: Any) -> str:
            try:
                parsed = datetime.fromisoformat(str(value or "").replace("Z", "+00:00"))
                if parsed.tzinfo is None:
                    parsed = parsed.replace(tzinfo=timezone.utc)
                return parsed.astimezone(beijing).date().isoformat()
            except (TypeError, ValueError):
                return str(value or "")[:10]
        for row in usage_rows:
            if row_day(row.get("created_at")) != safe_day:
                continue
            if str(row.get("status") or "") != "adjusted":
                result["requests"] += 1
                if not int(row.get("usage_known") or 0):
                    result["unknown_usage_requests"] += 1
                result["total_tokens"] += int(row.get("total_tokens") or 0)
            result["prompt_tokens"] += int(row.get("prompt_tokens") or 0)
            result["completion_tokens"] += int(row.get("completion_tokens") or 0)
        return result

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
                            preview: Dict[str, Any], expires_at: str,
                            conversation_id: Optional[str] = None) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO ai_tool_confirmations(id,tool_id,arguments_json,preview_json,status,expires_at,created_at,conversation_id) "
                "VALUES(?,?,?,?,?,?,?,?)",
                (confirmation_id, tool_id, json.dumps(arguments, ensure_ascii=False),
                 json.dumps(preview, ensure_ascii=False), "pending", expires_at, utc_now(), conversation_id),
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
                            result: Optional[Dict[str, Any]] = None) -> bool:
        if status not in {"completed", "failed"}:
            raise ValueError("invalid confirmation status")
        result_json = json.dumps(result, ensure_ascii=False)[:32000] if result is not None else None
        with self._connect() as conn:
            return bool(conn.execute(
                "UPDATE ai_tool_confirmations SET status=?, result_json=? "
                "WHERE id=? AND status='executing'",
                (status, result_json, confirmation_id),
            ).rowcount)

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

    @staticmethod
    def _confirmation_view(row: sqlite3.Row) -> Dict[str, Any]:
        item = dict(row)
        item["arguments"] = json.loads(item.pop("arguments_json") or "{}")
        item["preview"] = json.loads(item.pop("preview_json") or "{}")
        raw_result = item.pop("result_json", None)
        try:
            item["result"] = json.loads(raw_result) if raw_result else None
        except (TypeError, ValueError):
            item["result"] = None
        item["expired"] = (
            str(item.get("status") or "") in {"pending", "executing"}
            and str(item.get("expires_at") or "") < utc_now()
        )
        return item

    def get_confirmation(self, confirmation_id: str) -> Optional[Dict[str, Any]]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM ai_tool_confirmations WHERE id=?", (str(confirmation_id),),
            ).fetchone()
        return self._confirmation_view(row) if row is not None else None

    def pending_confirmation_for_conversation(self, conversation_id: str) -> Optional[Dict[str, Any]]:
        """Return the newest unexpired recoverable confirmation for a chat."""
        now = utc_now()
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM ai_tool_confirmations WHERE conversation_id=? "
                "AND status IN ('pending','executing') AND expires_at>=? "
                "ORDER BY created_at DESC,id DESC LIMIT 1",
                (str(conversation_id), now),
            ).fetchone()
        return self._confirmation_view(row) if row is not None else None

    def cancel_confirmation(self, confirmation_id: str) -> Optional[Dict[str, Any]]:
        """Atomically cancel an unclaimed confirmation.

        Once executing, the side effect may already have started and cannot be
        truthfully reported as cancelled.
        """
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT * FROM ai_tool_confirmations WHERE id=? AND status='pending' AND expires_at>=?",
                (str(confirmation_id), utc_now()),
            ).fetchone()
            if row is None:
                conn.execute("ROLLBACK")
                return None
            changed = conn.execute(
                "UPDATE ai_tool_confirmations SET status='cancelled',result_json=? "
                "WHERE id=? AND status='pending'",
                (json.dumps({"ok": False, "message": "用户已取消"}, ensure_ascii=False),
                 str(confirmation_id)),
            ).rowcount
            if changed != 1:
                conn.execute("ROLLBACK")
                return None
            conn.execute("COMMIT")
        return self.get_confirmation(confirmation_id)

    def list_recent_confirmations(self, limit: int = 10) -> list[Dict[str, Any]]:
        """Recent confirmation cards with an explicit expired flag, for the
        assistant to verify whether historical confirmation requests ever ran."""
        bounded = max(1, min(int(limit), 20))
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT id, tool_id, status, expires_at, created_at, confirmed_at, result_json "
                "FROM ai_tool_confirmations ORDER BY created_at DESC, id DESC LIMIT ?",
                (bounded,),
            ).fetchall()
        now = utc_now()
        result: List[Dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            item["expired"] = (
                str(item.get("status") or "") in ("pending", "executing")
                and str(item.get("expires_at") or "") < now
            )
            result.append(item)
        return result

    def delete_message(self, conversation_id: str, message_id: int) -> bool:
        clean_id = str(conversation_id or "").strip()
        if not clean_id:
            return False
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                removed = conn.execute(
                    "SELECT role,content FROM messages WHERE id=? AND conversation_id=?",
                    (int(message_id), clean_id),
                ).fetchone()
                conversation = conn.execute(
                    "SELECT title,created_at FROM conversations WHERE id=?", (clean_id,),
                ).fetchone()
                deleted = conn.execute(
                    "DELETE FROM messages WHERE id=? AND conversation_id=?",
                    (int(message_id), clean_id),
                ).rowcount
                if deleted and conversation is not None:
                    latest = conn.execute(
                        "SELECT created_at FROM messages WHERE conversation_id=? ORDER BY id DESC LIMIT 1",
                        (clean_id,),
                    ).fetchone()
                    title = str(conversation["title"] or "").strip()
                    removed_was_title = bool(
                        removed is not None and removed["role"] == "user"
                        and title == str(removed["content"] or "").strip()[:32]
                    )
                    if removed_was_title or latest is None:
                        first_user = conn.execute(
                            "SELECT content FROM messages WHERE conversation_id=? AND role='user' "
                            "ORDER BY id ASC LIMIT 1", (clean_id,),
                        ).fetchone()
                        title = str(first_user["content"] or "").strip()[:32] if first_user else "新对话"
                    updated_at = latest["created_at"] if latest else conversation["created_at"]
                    conn.execute(
                        "UPDATE conversations SET title=?,updated_at=? WHERE id=?",
                        (title or "新对话", updated_at, clean_id),
                    )
                conn.execute("COMMIT")
            except Exception:
                conn.execute("ROLLBACK")
                raise
        if deleted:
            self.enforce_conversation_storage(protected_conversation_id=clean_id)
        return bool(deleted)

    def promote_config(self, config_id: int) -> Optional[Dict[str, Any]]:
        """Move a config to the front of the enabled order (chat uses #1)."""
        target = int(config_id)
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT id FROM ai_provider_configs ORDER BY position ASC, id ASC"
            ).fetchall()
            ids = [int(row["id"]) for row in rows]
            if target not in ids:
                return None
            ids.remove(target)
            ids.insert(0, target)
            for index, row_id in enumerate(ids):
                conn.execute(
                    "UPDATE ai_provider_configs SET position=?, updated_at=? WHERE id=?",
                    (index, utc_now(), row_id),
                )
        return self.get_config(target)

    def move_config(self, config_id: int, direction: str) -> bool:
        """Swap a config with its upper/lower neighbor in the enabled order."""
        target = int(config_id)
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT id FROM ai_provider_configs ORDER BY position ASC, id ASC"
            ).fetchall()
            ids = [int(row["id"]) for row in rows]
            if target not in ids:
                return False
            index = ids.index(target)
            swap = index - 1 if direction == "up" else index + 1
            if not 0 <= swap < len(ids):
                return True  # already at the edge
            ids[index], ids[swap] = ids[swap], ids[index]
            for position, row_id in enumerate(ids):
                conn.execute(
                    "UPDATE ai_provider_configs SET position=?, updated_at=? WHERE id=?",
                    (position, utc_now(), row_id),
                )
        return True

    def delete_usage_record(self, usage_id: int) -> bool:
        with self._connect() as conn:
            return bool(conn.execute("DELETE FROM ai_usage WHERE id=?", (int(usage_id),)).rowcount)

    def record_usage_adjustment(self, config_id: int, target_total: int,
                                model_quota_tokens: Any = _UNSET) -> Optional[Dict[str, Any]]:
        """把某配置的累计用量调整为手动输入值。

        把平台后台读到的累计值保存为独立基准。任务用量行不被改写，
        后续任务从校准时的最后一行继续累加，删除对话也不会改变基准。
        """
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                row = conn.execute(
                    "SELECT * FROM ai_provider_configs WHERE id=?", (int(config_id),),
                ).fetchone()
                if row is None:
                    conn.execute("ROLLBACK")
                    return None
                usage_rows = conn.execute(
                    "SELECT * FROM ai_usage WHERE config_id=?", (int(config_id),)
                ).fetchall()
                current = self._effective_config_total(row, usage_rows)
                delta = int(target_total) - int(current)
                floor = conn.execute(
                    "SELECT COALESCE(MAX(id),0) AS id FROM ai_usage WHERE config_id=?",
                    (int(config_id),),
                ).fetchone()["id"]
                prior_target = row["manual_total_tokens"]
                # Re-calibrate even when the user enters the same baseline
                # value after new tasks have accumulated; otherwise the old
                # floor would keep those tasks added on top of the requested
                # target. Concurrent identical submissions still converge to
                # one update because the second read sees current == target.
                changed = prior_target is None or int(current) != int(target_total)
                adjustment_id = int(config_id) if changed else None
                if model_quota_tokens is not _UNSET:
                    conn.execute(
                        "UPDATE ai_provider_configs SET model_quota_tokens=?,manual_total_tokens=?,"
                        "manual_calibrated_at=?,manual_usage_floor_id=?,usage_record_hidden=0,updated_at=? WHERE id=?",
                        (model_quota_tokens, int(target_total), utc_now(), int(floor), utc_now(), int(config_id)),
                    )
                elif changed:
                    conn.execute(
                        "UPDATE ai_provider_configs SET manual_total_tokens=?,manual_calibrated_at=?,"
                        "manual_usage_floor_id=?,usage_record_hidden=0,updated_at=? WHERE id=?",
                        (int(target_total), utc_now(), int(floor), utc_now(), int(config_id)),
                    )
                else:
                    conn.execute(
                        "UPDATE ai_provider_configs SET usage_record_hidden=0,updated_at=? WHERE id=?",
                        (utc_now(), int(config_id)),
                    )
                conn.execute("COMMIT")
            except Exception:
                conn.execute("ROLLBACK")
                raise
        return {"id": adjustment_id, "delta": delta, "target": int(target_total)}

    def delete_config_usage_record(self, config_id: int) -> bool:
        """Delete a quota/calibration card without deleting its API config.

        Provider credentials, endpoint/model settings and every immutable task
        usage row remain intact. A later calibration makes the card visible
        again.
        """
        with self._connect() as conn:
            return bool(conn.execute(
                "UPDATE ai_provider_configs SET model_quota_tokens=NULL,manual_total_tokens=NULL,"
                "manual_calibrated_at=NULL,manual_usage_floor_id=NULL,usage_record_hidden=1,updated_at=? "
                "WHERE id=?",
                (utc_now(), int(config_id)),
            ).rowcount)

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
