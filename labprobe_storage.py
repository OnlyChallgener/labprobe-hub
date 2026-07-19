"""SQLite persistence, migration and revision log for LabProbe Hub.

The public Hub code historically stores JSON documents below DATA_DIR.  This
module keeps that document-shaped API, but persists the documents in SQLite and
records fine grained changes in the same transaction.  Old JSON files are only
read during the first migration and are copied to a timestamped backup first.
"""

from __future__ import annotations

import json
import os
import shutil
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


SCHEMA_VERSION = 1


def _json_text(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")



class SQLiteStore:
    def __init__(self, data_dir: Path, backups_dir: Path, db_path: Optional[Path] = None):
        self.data_dir = data_dir.resolve()
        self.backups_dir = backups_dir.resolve()
        self.db_path = (db_path or (self.data_dir / "labprobe.db")).resolve()
        self._lock = threading.RLock()
        self.migration_result: Dict[str, Any] = {}

    @contextmanager
    def connect(self):
        conn = sqlite3.connect(str(self.db_path), timeout=15, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=15000")
        try:
            yield conn
        finally:
            conn.close()

    def initialize(self) -> Dict[str, Any]:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.backups_dir.mkdir(parents=True, exist_ok=True)
        existed = self.db_path.exists()
        try:
            with self._lock, self.connect() as conn:
                conn.execute("PRAGMA journal_mode=WAL")
                conn.execute("PRAGMA synchronous=FULL")
                self._create_schema(conn)
            if not existed:
                self.migration_result = self._migrate_json_once()
            else:
                self.migration_result = {"status": "existing", "database": str(self.db_path)}
            with self._lock, self.connect() as conn:
                if self.current_revision(conn) == 0:
                    conn.execute(
                        "INSERT INTO revisions(entity,operation,entity_key,payload_json,created_at) VALUES(?,?,?,?,?)",
                        ("system", "baseline", "database", None, _now()),
                    )
            self.integrity_check()
            return self.migration_result
        except Exception:
            if not existed:
                for suffix in ("", "-wal", "-shm"):
                    candidate = Path(str(self.db_path) + suffix)
                    if candidate.exists():
                        candidate.unlink()
            raise

    def _create_schema(self, conn: sqlite3.Connection) -> None:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version INTEGER PRIMARY KEY,
                applied_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS documents (
                key TEXT PRIMARY KEY,
                value_json TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS revisions (
                revision INTEGER PRIMARY KEY AUTOINCREMENT,
                entity TEXT NOT NULL,
                operation TEXT NOT NULL,
                entity_key TEXT NOT NULL,
                payload_json TEXT,
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_revisions_entity_revision
                ON revisions(entity, revision);
            """
        )
        row = conn.execute("SELECT MAX(version) AS v FROM schema_migrations").fetchone()
        current = int(row["v"] or 0)
        if current > SCHEMA_VERSION:
            raise RuntimeError(f"database schema {current} is newer than supported {SCHEMA_VERSION}")
        if current < 1:
            conn.execute(
                "INSERT INTO schema_migrations(version, applied_at) VALUES(?, ?)",
                (1, _now()),
            )

    def _json_files(self) -> List[Path]:
        return sorted(
            path for path in self.data_dir.rglob("*.json")
            if self.backups_dir not in path.parents and path.is_file()
        )

    def _migrate_json_once(self) -> Dict[str, Any]:
        files = self._json_files()
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        backup_root = self.backups_dir / f"json-migration-{stamp}"
        parsed: List[Tuple[str, Any, Path]] = []
        for source in files:
            relative = source.relative_to(self.data_dir).as_posix()
            try:
                value = json.loads(source.read_text(encoding="utf-8"))
            except Exception as exc:
                raise RuntimeError(f"cannot migrate invalid JSON {relative}: {exc}") from exc
            parsed.append((relative, value, source))

        if files:
            backup_root.mkdir(parents=True, exist_ok=False)
            for _, _, source in parsed:
                target = backup_root / source.relative_to(self.data_dir)
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, target)
                target.chmod(0o444)

        with self._lock, self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                for key, value, _ in parsed:
                    conn.execute(
                        "INSERT OR REPLACE INTO documents(key,value_json,updated_at) VALUES(?,?,?)",
                        (key, _json_text(value), _now()),
                    )
                conn.execute("COMMIT")
            except Exception:
                conn.execute("ROLLBACK")
                raise

        with self.connect() as conn:
            count = int(conn.execute("SELECT COUNT(*) AS n FROM documents").fetchone()["n"])
        if count != len(parsed):
            raise RuntimeError(f"JSON migration verification failed: expected {len(parsed)}, got {count}")
        return {
            "status": "migrated" if parsed else "empty",
            "documents": count,
            "backup": str(backup_root) if parsed else "",
            "database": str(self.db_path),
        }

    def integrity_check(self) -> None:
        with self.connect() as conn:
            result = str(conn.execute("PRAGMA integrity_check").fetchone()[0])
            if result.lower() != "ok":
                raise RuntimeError(f"SQLite integrity check failed: {result}")

    def document_key(self, path: Path) -> str:
        resolved = path.resolve()
        try:
            return resolved.relative_to(self.data_dir).as_posix()
        except ValueError as exc:
            raise ValueError(f"document path outside DATA_DIR: {resolved}") from exc

    def load(self, path: Path, default: Any) -> Any:
        key = self.document_key(path)
        with self._lock, self.connect() as conn:
            row = conn.execute("SELECT value_json FROM documents WHERE key=?", (key,)).fetchone()
        if row is None:
            return default
        try:
            return json.loads(row["value_json"])
        except Exception:
            return default

    def save(self, path: Path, value: Any) -> int:
        key = self.document_key(path)
        with self._lock, self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                row = conn.execute("SELECT value_json FROM documents WHERE key=?", (key,)).fetchone()
                old = json.loads(row["value_json"]) if row else None
                encoded = _json_text(value)
                if row is not None and row["value_json"] == encoded:
                    conn.execute("COMMIT")
                    return self.current_revision(conn)
                conn.execute(
                    "INSERT INTO documents(key,value_json,updated_at) VALUES(?,?,?) "
                    "ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json,updated_at=excluded.updated_at",
                    (key, encoded, _now()),
                )
                for entity, operation, entity_key, payload in self._changes_for_document(key, old, value):
                    conn.execute(
                        "INSERT INTO revisions(entity,operation,entity_key,payload_json,created_at) VALUES(?,?,?,?,?)",
                        (entity, operation, entity_key, None if payload is None else _json_text(payload), _now()),
                    )
                conn.execute("COMMIT")
                return self.current_revision(conn)
            except Exception:
                conn.execute("ROLLBACK")
                raise

    @staticmethod
    def _row_key(item: Dict[str, Any], fallback: str) -> str:
        return str(item.get("mac") or item.get("id") or item.get("date") or fallback).strip().lower()

    def _list_diff(self, entity: str, old: Iterable[Any], new: Iterable[Any]) -> List[Tuple[str, str, str, Any]]:
        old_map = {self._row_key(x, str(i)): x for i, x in enumerate(old or []) if isinstance(x, dict)}
        new_map = {self._row_key(x, str(i)): x for i, x in enumerate(new or []) if isinstance(x, dict)}
        changes: List[Tuple[str, str, str, Any]] = []
        for key, value in new_map.items():
            previous = old_map.get(key)
            if previous != value:
                operation = "delete" if bool(value.get("deleted")) else "upsert"
                changes.append((entity, operation, key, None if operation == "delete" else value))
        for key in old_map.keys() - new_map.keys():
            changes.append((entity, "delete", key, None))
        return changes

    def _changes_for_document(self, key: str, old: Any, new: Any) -> List[Tuple[str, str, str, Any]]:
        if key == "devices.json":
            old_obj = old if isinstance(old, dict) else {}
            new_obj = new if isinstance(new, dict) else {}
            old_meta = {
                "onlineDeviceCount": old_obj.get("onlineDeviceCount", len(old_obj.get("online", []) or [])),
                "total": old_obj.get("total", 0),
            }
            new_meta = {
                "onlineDeviceCount": new_obj.get("onlineDeviceCount", len(new_obj.get("online", []) or [])),
                "total": new_obj.get("total", 0),
            }
            meta_changes = []
            if old_meta != new_meta:
                meta_changes.append(("device_meta", "replace", "devices", new_meta))
            return (
                self._list_diff("device", old_obj.get("watched", []), new_obj.get("watched", []))
                + self._list_diff("online_device", old_obj.get("online", []), new_obj.get("online", []))
                + meta_changes
            )
        if key == "events.json":
            return self._list_diff("event", old if isinstance(old, list) else [], new if isinstance(new, list) else [])
        if key == "state.json":
            def stable_status(value: Any) -> Any:
                if not isinstance(value, dict):
                    return value
                clean = json.loads(json.dumps(value))
                clean.pop("updatedAt", None)
                router = clean.get("router")
                if isinstance(router, dict):
                    router.pop("devicesUpdatedAt", None)
                hub = clean.get("hub")
                if isinstance(hub, dict):
                    hub.pop("updatedAt", None)
                return clean
            if stable_status(old) == stable_status(new):
                return []
            return [("status", "replace", "status", new)]
        return [("document", "replace", key, new)]

    @staticmethod
    def current_revision(conn: Optional[sqlite3.Connection] = None) -> int:
        if conn is None:
            raise ValueError("connection required")
        row = conn.execute("SELECT COALESCE(MAX(revision),0) AS revision FROM revisions").fetchone()
        return int(row["revision"] or 0)

    def revision_info(self) -> Dict[str, int]:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT COALESCE(MIN(revision),0) AS oldest, COALESCE(MAX(revision),0) AS current FROM revisions"
            ).fetchone()
        return {"oldestRevision": int(row["oldest"]), "revision": int(row["current"]), "sequence": int(row["current"])}

    def changes_since(self, since: int, limit: int = 500) -> Dict[str, Any]:
        limit = max(1, min(int(limit), 1000))
        with self.connect() as conn:
            row = conn.execute(
                "SELECT COALESCE(MIN(revision),0) AS oldest, COALESCE(MAX(revision),0) AS current FROM revisions"
            ).fetchone()
            info = {"oldestRevision": int(row["oldest"]), "revision": int(row["current"]), "sequence": int(row["current"])}
            oldest = info["oldestRevision"]
            current = info["revision"]
            full_required = since < 0 or (oldest > 0 and since < oldest - 1) or since > current
            if full_required:
                return {**info, "fromRevision": since, "fullRequired": True, "hasMore": False, "changes": []}
            rows = conn.execute(
                "SELECT revision,entity,operation,entity_key,payload_json,created_at "
                "FROM revisions WHERE revision>? ORDER BY revision LIMIT ?",
                (since, limit + 1),
            ).fetchall()
        has_more = len(rows) > limit
        rows = rows[:limit]
        changes = [{
            "revision": int(row["revision"]),
            "sequence": int(row["revision"]),
            "entity": row["entity"],
            "operation": row["operation"],
            "key": row["entity_key"],
            "payload": json.loads(row["payload_json"]) if row["payload_json"] else None,
            "createdAt": row["created_at"],
        } for row in rows]
        next_revision = int(rows[-1]["revision"]) if rows else since
        return {
            **info,
            "fromRevision": since,
            "nextRevision": next_revision,
            "fullRequired": False,
            "hasMore": has_more,
            "changes": changes,
        }

    def status(self) -> Dict[str, Any]:
        info = self.revision_info()
        with self.connect() as conn:
            schema = int(conn.execute("SELECT COALESCE(MAX(version),0) FROM schema_migrations").fetchone()[0])
            documents = int(conn.execute("SELECT COUNT(*) FROM documents").fetchone()[0])
        return {**info, "schemaVersion": schema, "documents": documents, "path": str(self.db_path), "ok": True}
