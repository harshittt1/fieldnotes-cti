"""Merge duplicate MISP event rows by UUID, retaining source provenance.

Default mode is read-only. ``--apply`` archives duplicate rows before removing
them and records all originating feeds in the canonical event's ``sources``.
"""
import argparse
from pymongo import ReplaceOne
from backend.db import db

EVENTS = db.events
ARCHIVE = db.events_quarantine_duplicate_misp
BASE = {"record_type": "misp_event", "event_uuid": {"$type": "string", "$ne": ""}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true", help="archive duplicate rows, then keep one event per UUID")
    args = parser.parse_args()

    missing_uuid = EVENTS.count_documents({"record_type": "misp_event", "$or": [{"event_uuid": {"$exists": False}}, {"event_uuid": None}, {"event_uuid": ""}]})
    groups = list(EVENTS.aggregate([
        {"$match": BASE},
        {"$group": {"_id": "$event_uuid", "ids": {"$push": "$_id"}, "sources": {"$addToSet": "$source"}, "all_sources": {"$addToSet": "$sources"}, "n": {"$sum": 1}}},
        {"$match": {"n": {"$gt": 1}}},
    ], allowDiskUse=True, maxTimeMS=30000))
    extras = sum(row["n"] - 1 for row in groups)
    print(f"MISP event rows: {EVENTS.count_documents(BASE):,}")
    print(f"Distinct MISP event UUIDs: {EVENTS.distinct('event_uuid', BASE).__len__():,}")
    print(f"Duplicate UUID groups: {len(groups):,}; extra rows to archive: {extras:,}")
    print(f"MISP rows missing a UUID: {missing_uuid:,}")
    if missing_uuid:
        raise RuntimeError("MISP rows without event_uuid need manual review; no changes were made.")
    if not args.apply:
        print("Dry run only. Re-run with --apply to keep one event per UUID.")
        return
    if extras == 0:
        EVENTS.create_index("event_uuid", unique=True)
        print("No duplicates. Unique event_uuid index is ready.")
        return

    if ARCHIVE.estimated_document_count() not in (0, extras):
        raise RuntimeError("Duplicate archive collection contains an unexpected count; refusing to continue.")
    to_delete = []
    archived_ops = []
    for group in groups:
        docs = list(EVENTS.find({"_id": {"$in": group["ids"]}}).sort("_id", 1))
        canonical = docs[0]
        origins = set(group.get("sources") or [])
        for arr in group.get("all_sources") or []:
            origins.update(arr or [])
        origins.discard(None)
        canonical_source = canonical.get("source")
        if canonical_source:
            origins.add(canonical_source)
        EVENTS.update_one({"_id": canonical["_id"]}, {"$set": {"sources": sorted(origins)}})
        for duplicate in docs[1:]:
            archived_ops.append(ReplaceOne({"_id": duplicate["_id"]}, duplicate, upsert=True))
            to_delete.append(duplicate["_id"])
            if len(archived_ops) >= 500:
                ARCHIVE.bulk_write(archived_ops, ordered=False)
                archived_ops.clear()
        if canonical_source:
            EVENTS.update_many({"event_uuid": group["_id"], "record_type": "misp_event"}, {"$addToSet": {"sources": canonical_source}})
    if archived_ops:
        ARCHIVE.bulk_write(archived_ops, ordered=False)
    if ARCHIVE.count_documents({}) != extras:
        raise RuntimeError("Duplicate archive did not verify; active events were left in place.")
    for start in range(0, len(to_delete), 500):
        EVENTS.delete_many({"_id": {"$in": to_delete[start:start + 500]}})

    EVENTS.update_many({"record_type": "misp_event", "sources": {"$exists": False}}, [{"$set": {"sources": ["$source"]}}])
    remaining = list(EVENTS.aggregate([
        {"$match": BASE}, {"$group": {"_id": "$event_uuid", "n": {"$sum": 1}}}, {"$match": {"n": {"$gt": 1}}}, {"$limit": 1}
    ], maxTimeMS=30000))
    if remaining:
        raise RuntimeError("Duplicate verification failed; full duplicate archive is retained.")
    EVENTS.create_index("event_uuid", unique=True)
    print(f"Archived {extras:,} duplicate rows. Canonical MISP events: {EVENTS.count_documents(BASE):,}.")
    print("Original duplicate documents remain in events_quarantine_duplicate_misp.")


if __name__ == "__main__":
    main()
