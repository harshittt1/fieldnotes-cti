import requests
from pymongo import ASCENDING

from backend.db import indicators_collection
from backend.models import normalize_urlhaus
from backend.config import URLHAUS_API_KEY


URLHAUS_URL = (
    f"https://urlhaus-api.abuse.ch/v2/files/exports/"
    f"{URLHAUS_API_KEY}/recent.json"
)


def fetch_urlhaus():
    """Fetch the current URLhaus recent URL export."""

    print("Fetching URLhaus...")

    response = requests.get(
        URLHAUS_URL,
        timeout=120
    )

    response.raise_for_status()

    data = response.json()

    if not isinstance(data, dict):
        raise ValueError(
            "URLhaus response is not a dictionary"
        )

    records = []

    # URLhaus JSON export contains lists inside
    # a dictionary structure.
    for value in data.values():

        if isinstance(value, list):

            for record in value:

                if isinstance(record, dict):
                    records.append(record)

    print(
        f"Downloaded {len(records)} URLhaus records."
    )

    return records


def prepare_records(raw_records):
    """Normalize and deduplicate URLhaus URLs."""

    normalized = []

    seen = set()

    for record in raw_records:

        if not isinstance(record, dict):
            continue

        url = record.get("url")

        if not url:
            continue

        dedup_key = str(url).strip().lower()

        if dedup_key in seen:
            continue

        seen.add(dedup_key)

        normalized.append(
            normalize_urlhaus(record)
        )

    return normalized


def create_indexes():
    """Create URLhaus-compatible indexes."""

    print("Creating URLhaus indexes...")

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

    print("Indexes created.")


def insert_records(records):
    """Insert URLhaus records into indicators."""

    if not records:
        print("No records to insert.")
        return 0

    print(
        f"Inserting {len(records)} URLhaus records..."
    )

    result = indicators_collection.insert_many(
        records,
        ordered=False
    )

    count = len(result.inserted_ids)

    print(
        f"Inserted {count} URLhaus records."
    )

    return count


def main():

    print("=" * 60)
    print("URLHAUS INGESTION")
    print("=" * 60)

    # --------------------------------------------------------
    # 1. Fetch
    # --------------------------------------------------------

    raw_records = fetch_urlhaus()

    # --------------------------------------------------------
    # 2. Normalize + deduplicate
    # --------------------------------------------------------

    records = prepare_records(
        raw_records
    )

    print(
        f"Prepared {len(records)} unique URLhaus records."
    )

    # --------------------------------------------------------
    # 3. Safety check
    # --------------------------------------------------------

    existing_count = (
        indicators_collection.count_documents(
            {
                "source": "URLhaus"
            }
        )
    )

    print(
        f"Existing URLhaus documents: "
        f"{existing_count}"
    )

    if existing_count > 0:

        print(
            "\nURLhaus data already exists."
        )

        print(
            "No new URLhaus records will be inserted."
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
        indicators_collection.count_documents(
            {
                "source": "URLhaus"
            }
        )
    )

    print(
        "\nFinal URLhaus document count:",
        final_count
    )

    print("\nURLhaus ingestion completed.")


if __name__ == "__main__":
    main()