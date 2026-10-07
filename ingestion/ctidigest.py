import requests
from pymongo import ASCENDING

from backend.db import ctidigest_collection
from backend.models import normalize_ctidigest


CTIDIGEST_URL = "https://ctidigest.com/iocs.json"


def fetch_ctidigest():
    """Download the current CTIDigest IOC feed."""

    print("Fetching CTIDigest...")

    response = requests.get(
        CTIDIGEST_URL,
        timeout=120
    )

    response.raise_for_status()

    data = response.json()

    if not isinstance(data, list):
        raise ValueError(
            "CTIDigest response is not a list"
        )

    print(
        f"Downloaded {len(data)} records."
    )

    return data


def prepare_records(raw_records):
    """
    Normalize and deduplicate CTIDigest records.
    """

    normalized = []

    seen = set()

    for record in raw_records:

        if not isinstance(record, dict):
            continue

        value = record.get("value")

        if not value:
            continue

        # Normalize IOC value for deduplication
        dedup_key = (
            str(value).strip().lower(),
            str(record.get("type", "")).strip().lower()
        )

        if dedup_key in seen:
            continue

        seen.add(dedup_key)

        normalized_record = normalize_ctidigest(
            record
        )

        normalized.append(
            normalized_record
        )

    return normalized


def create_indexes():
    """Create indexes for efficient searches."""

    print("Creating CTIDigest indexes...")

    ctidigest_collection.create_index(
        [
            ("value", ASCENDING)
        ]
    )

    ctidigest_collection.create_index(
        [
            ("type", ASCENDING)
        ]
    )

    ctidigest_collection.create_index(
        [
            ("source_name", ASCENDING)
        ]
    )

    print("Indexes created.")


def insert_records(records):
    """Insert normalized records into MongoDB."""

    if not records:
        print("No records to insert.")
        return 0

    print(
        f"Inserting {len(records)} records into MongoDB..."
    )

    result = ctidigest_collection.insert_many(
        records,
        ordered=False
    )

    inserted_count = len(
        result.inserted_ids
    )

    print(
        f"Inserted {inserted_count} records."
    )

    return inserted_count


def main():

    print("=" * 60)
    print("CTIDIGEST INGESTION")
    print("=" * 60)

    # --------------------------------------------------------
    # 1. Fetch
    # --------------------------------------------------------

    raw_records = fetch_ctidigest()

    # --------------------------------------------------------
    # 2. Normalize + deduplicate
    # --------------------------------------------------------

    records = prepare_records(
        raw_records
    )

    print(
        f"Prepared {len(records)} unique records."
    )

    # --------------------------------------------------------
    # 3. Prevent accidental duplicate ingestion
    # --------------------------------------------------------

    existing_count = (
        ctidigest_collection.count_documents({})
    )

    print(
        f"Existing CTIDigest documents: "
        f"{existing_count}"
    )

    if existing_count > 0:

        print(
            "\nCTIDigest collection is not empty."
        )

        print(
            "No new records will be inserted."
        )

        return

    # --------------------------------------------------------
    # 4. Insert
    # --------------------------------------------------------

    insert_records(records)

    # --------------------------------------------------------
    # 5. Indexes
    # --------------------------------------------------------

    create_indexes()

    # --------------------------------------------------------
    # 6. Verify
    # --------------------------------------------------------

    final_count = (
        ctidigest_collection.count_documents({})
    )

    print(
        "\nFinal CTIDigest document count:",
        final_count
    )

    print("\nCTIDigest ingestion completed.")


if __name__ == "__main__":
    main()