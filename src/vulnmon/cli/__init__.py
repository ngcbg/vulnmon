"""Local development CLI, not a network service or production management API."""
import argparse
import json
import os
import sqlite3
import sys

from vulnmon.common.contracts import load
from vulnmon.correlatord.persistence.sqlite import Store
from vulnmon.correlatord.service import Core


def main(argv=None):
    parser = argparse.ArgumentParser(prog="vulnctl")
    parser.add_argument("--db", required=True, help="local development database")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("init")
    for name in ("ingest-inventory", "ingest-advisory"):
        sub.add_parser(name).add_argument("path")
    corr = sub.add_parser("correlate")
    corr.add_argument("--batch-size", type=int, default=100)
    corr.add_argument("--max-batches", type=int, default=1)
    sub.add_parser("status")
    for name in ("findings", "events"):
        p = sub.add_parser(name)
        p.add_argument("--after", type=int, default=0)
        p.add_argument("--limit", type=int, default=100)
    args = parser.parse_args(argv)
    os.umask(0o077)
    try:
        if args.command in ("findings", "events") and not (
            args.after >= 0 and 1 <= args.limit <= 500
        ):
            raise ValueError("invalid pagination")
        payload = load(args.path) if args.command.startswith("ingest-") else None
        with Store(args.db) as store:
            core = Core(store)
            if args.command == "ingest-inventory":
                result = core.ingest_inventory(payload)
            elif args.command == "ingest-advisory":
                result = core.ingest_advisory(payload)
            elif args.command == "correlate":
                result = core.correlate(args.batch_size, args.max_batches)
            elif args.command == "findings":
                result = store.findings(args.after, args.limit)
            elif args.command == "events":
                result = store.events(args.after, args.limit)
            else:
                result = store.status()
        print(json.dumps(result, indent=2, ensure_ascii=True))
        return 0
    except (OSError, ValueError, RuntimeError, sqlite3.Error) as exc:
        print(f"vulnctl: {exc}", file=sys.stderr)
        return 1
