#!/usr/bin/env python3
"""Compact a LabProbe SQLite database after the old unbounded revision bug.

Stop the Hub container before using --vacuum. The script creates a SQLite backup
before modifying the source database. Current documents/configuration are kept;
only old revision history is trimmed.
"""

from __future__ import annotations

import argparse
import sqlite3
from datetime import datetime
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--database", default="/app/data/labprobe.db")
    parser.add_argument("--backup-dir", default="/app/backups")
    parser.add_argument("--keep-revisions", type=int, default=5000)
    parser.add_argument("--vacuum", action="store_true")
    args = parser.parse_args()

    database = Path(args.database).resolve()
    if not database.is_file():
        parser.error(f"database not found: {database}")
    backup_dir = Path(args.backup_dir).resolve()
    backup_dir.mkdir(parents=True, exist_ok=True)
    backup = backup_dir / f"labprobe-pre-repair-{datetime.now():%Y%m%d-%H%M%S}.db"

    source = sqlite3.connect(str(database), timeout=60)
    source.execute("PRAGMA busy_timeout=60000")
    target = sqlite3.connect(str(backup))
    source.backup(target)
    target.close()

    keep = max(1, args.keep_revisions)
    source.execute("BEGIN IMMEDIATE")
    cutoff = source.execute(
        "SELECT revision FROM revisions ORDER BY revision DESC LIMIT 1 OFFSET ?",
        (keep - 1,),
    ).fetchone()
    if cutoff is not None:
        source.execute("DELETE FROM revisions WHERE revision < ?", (int(cutoff[0]),))
    source.commit()
    source.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    if args.vacuum:
        source.execute("VACUUM")
    count = int(source.execute("SELECT COUNT(*) FROM revisions").fetchone()[0])
    source.close()

    print(f"backup={backup}")
    print(f"revisions={count}")
    print(f"database={database}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
