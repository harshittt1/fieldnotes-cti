"""Recoverably quarantine synthetic feed rows that were put in events.

Default mode is read-only. ``--apply`` copies eligible documents to the
quarantine collection, verifies the copy, and then removes only those copies
from the active events collection. The quarantine collection is retained.
"""
import argparse
from collections import Counter
from pathlib import Path
from bson import json_util
from pymongo import ReplaceOne

from backend.db import db

LEGACY_FEED_SOURCES = ["ThreatFox", "URLhaus", "MalwareBazaar", "CTIDigest"]
QUARANTINE = "events_quarantine_legacy_synthetic"
BAD_ROWS = {
    "record_type": {"$exists": False},
    "source": {"$in": LEGACY_FEED_SOURCES},
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true", help="archive, verify, then remove matching rows from events")
    parser.add_argument("--restore", action="store_true", help="restore quarantined documents to events without removing the archive copy")
    parser.add_argument("--restore-file", type=Path, help="read the retained JSONL.GZ backup created outside MongoDB")
    args = parser.parse_args()
    if args.apply and args.restore:
        parser.error("choose either --apply or --restore")

    valid = db.events.count_documents({"record_type": "misp_event"})
    malformed = db.events.count_documents(BAD_ROWS)
    sources = Counter()
    for row in db.events.aggregate([
        {"$match": BAD_ROWS},
        {"$group": {"_id": "$source", "count": {"$sum": 1}}},
    ]):
        sources[row["_id"]] = row["count"]
    print(f"Valid MISP events: {valid:,}")
    print(f"Feed-like rows missing record_type: {malformed:,}")
    for source, count in sorted(sources.items()):
        print(f"  {source}: {count:,}")
    if args.restore:
        quarantine = db[QUARANTINE]
        restored = 0
        batch = []
        if args.restore_file:
            import gzip
            if not args.restore_file.exists():
                raise RuntimeError(f"Backup file not found: {args.restore_file}")
            with gzip.open(args.restore_file, "rt", encoding="utf-8") as backup:
                rows = (json_util.loads(line) for line in backup if line.strip())
                for row in rows:
                    if db.events.find_one({"_id": row["_id"]}, {"_id": 1}):
                        raise RuntimeError(f"Event {row['_id']} is already present; refusing to overwrite it.")
                    batch.append(row)
                    if len(batch) >= 1000:
                        db.events.insert_many(batch, ordered=True)
                        restored += len(batch)
                        batch.clear()
        else:
            rows = quarantine.find({}, batch_size=1000)
            for row in rows:
                if db.events.find_one({"_id": row["_id"]}, {"_id": 1}):
                    raise RuntimeError(f"Event {row['_id']} is already present; refusing to overwrite it.")
                batch.append(row)
                if len(batch) >= 1000:
                    db.events.insert_many(batch, ordered=True)
                    restored += len(batch)
                    batch.clear()
        if batch:
            db.events.insert_many(batch, ordered=True)
            restored += len(batch)
        print(f"Restored {restored:,} quarantined documents; archive copy was retained.")
        return
    if not args.apply:
        print("Dry run only. Re-run with --apply to retain a quarantine copy and remove these rows from events.")
        return
    if not malformed:
        print("Nothing to quarantine.")
        return

    quarantine = db[QUARANTINE]
    copied = 0
    operations = []
    for row in db.events.find(BAD_ROWS, batch_size=1000):
        operations.append(ReplaceOne({"_id": row["_id"]}, row, upsert=True))
        if len(operations) >= 1000:
            quarantine.bulk_write(operations, ordered=False)
            copied += len(operations)
            print(f"Archived or confirmed {copied:,}/{malformed:,} rows…", flush=True)
            operations.clear()
    if operations:
        quarantine.bulk_write(operations, ordered=False)
        copied += len(operations)
        print(f"Archived or confirmed {copied:,}/{malformed:,} rows…", flush=True)

    archived = quarantine.count_documents({})
    if archived != malformed:
        raise RuntimeError(f"Archive verification failed (expected {malformed}, copied {copied}, archived {archived}); source rows were left in events.")

    deleted = db.events.delete_many(BAD_ROWS).deleted_count
    if deleted != malformed:
        raise RuntimeError(f"Moved {deleted} of {malformed} source rows. The complete archive remains in {QUARANTINE}.")

    remaining_bad = db.events.count_documents(BAD_ROWS)
    final_valid = db.events.count_documents({"record_type": "misp_event"})
    if remaining_bad or final_valid != valid:
        raise RuntimeError(f"Post-migration check failed. remaining malformed={remaining_bad}, valid before={valid}, after={final_valid}. Archive: {QUARANTINE}")
    print(f"Quarantined and removed {deleted:,} synthetic feed rows from events.")
    print(f"MISP events preserved: {final_valid:,}.")
    print(f"Recoverable originals remain in collection {QUARANTINE}.")


if __name__ == "__main__":
    main()
