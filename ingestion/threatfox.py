import requests
from pymongo import ASCENDING

from backend.db import indicators_collection
from backend.models import normalize_threatfox
from backend.config import THREATFOX_API_KEY


THREATFOX_API = "https://threatfox-api.abuse.ch/api/v1/"


def fetch_threatfox():
    """Fetch the latest 7 days of ThreatFox IOCs."""

    print("Fetching ThreatFox...")

    headers = {
        "Auth-Key": THREATFOX_API_KEY,
        "Content-Type": "application/json"
    }

    payload = {
        "query": "get_iocs",
        "days": 7
    }

    response = requests.post(
        THREATFOX_API,
        headers=headers,
        json=payload,
        timeout=120
    )

    response.raise_for_status()

    result = response.json()

    if result.get("query_status") != "ok":
        raise ValueError(
            f"ThreatFox query failed: {result}"
        )

    records = result.get("data", [])

    if not isinstance(records, list):
        raise ValueError(
            "ThreatFox data is not a list"
        )

    print(
        f"Downloaded {len(records)} ThreatFox records."
    )

    return records


def prepare_records(raw_records):
    """Normalize and deduplicate ThreatFox records."""

    normalized = []

    seen = set()

    for record in raw_records:

        if not isinstance(record, dict):
            continue

        ioc = record.get("ioc")

        if not ioc:
            continue

        dedup_key = (
            str(ioc).strip().lower(),
            str(record.get("ioc_type", "")).strip().lower()
        )

        if dedup_key in seen:
            continue

        seen.add(dedup_key)

        normalized.append(
            normalize_threatfox(record)
        )

    return normalized


def create_indexes():
    """Create indexes for ThreatFox indicators."""

    print("Creating ThreatFox indexes...")

    indicators_collection.create_index(
        [
            ("value", ASCENDING)
        ]
    )

    indicators_collection.create_index(
        [
            ("type", ASCENDING)
        ]
    )

    indicators_collection.create_index(
        [
            ("source", ASCENDING)
        ]
    )

    indicators_collection.create_index(
        [
            ("source_id", ASCENDING)
        ]
    )

    print("Indexes created.")


def insert_records(records):
    """Insert ThreatFox records into MongoDB."""

    if not records:
        print("No records to insert.")
        return 0

    print(
        f"Inserting {len(records)} ThreatFox records..."
    )

    result = indicators_collection.insert_many(
        records,
        ordered=False
    )

    count = len(result.inserted_ids)

    print(
        f"Inserted {count} ThreatFox records."
    )

    return count


def main():

    print("=" * 60)
    print("THREATFOX INGESTION")
    print("=" * 60)

    # --------------------------------------------------------
    # Fetch
    # --------------------------------------------------------

    raw_records = fetch_threatfox()

    # --------------------------------------------------------
    # Normalize + deduplicate
    # --------------------------------------------------------

    records = prepare_records(
        raw_records
    )

    print(
        f"Prepared {len(records)} unique ThreatFox records."
    )

    # --------------------------------------------------------
    # Safety check
    # --------------------------------------------------------

    existing_count = (
        indicators_collection.count_documents(
            {
                "source": "ThreatFox"
            }
        )
    )

    print(
        f"Existing ThreatFox documents: "
        f"{existing_count}"
    )

    if existing_count > 0:

        print(
            "\nThreatFox data already exists."
        )

        print(
            "No new ThreatFox records will be inserted."
        )

        return

    # --------------------------------------------------------
    # Insert
    # --------------------------------------------------------

    insert_records(records)

    # --------------------------------------------------------
    # Indexes
    # --------------------------------------------------------

    create_indexes()

    # --------------------------------------------------------
    # Verify
    # --------------------------------------------------------

    final_count = (
        indicators_collection.count_documents(
            {
                "source": "ThreatFox"
            }
        )
    )

    print(
        "\nFinal ThreatFox document count:",
        final_count
    )

    print("\nThreatFox ingestion completed.")


if __name__ == "__main__":
    main()