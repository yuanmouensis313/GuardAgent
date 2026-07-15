from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from guardd.config import Settings
from guardd.security import sha256_bytes


def main() -> None:
    parser = argparse.ArgumentParser(description="Create a consistent operator-owned GuardAgent SQLite backup")
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    settings = Settings.from_env()
    destination = args.destination.expanduser().resolve()
    if not settings.db_path.is_file():
        raise SystemExit(f"GuardAgent database does not exist: {settings.db_path}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    source = sqlite3.connect(settings.db_path)
    target = sqlite3.connect(destination)
    try:
        source.backup(target)
        integrity = target.execute("PRAGMA integrity_check").fetchone()[0]
    finally:
        target.close()
        source.close()
    digest = sha256_bytes(destination.read_bytes())
    print(json.dumps({"created_at": datetime.now(timezone.utc).isoformat(), "destination": str(destination), "sha256": digest, "integrity": integrity}, indent=2))
    if integrity != "ok":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
