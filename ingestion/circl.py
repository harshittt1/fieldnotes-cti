import requests

from backend.db import events_collection, indicators_collection
from backend.models import normalize_misp_event, normalize_misp_indicator


CIRCL_URL = "https://www.circl.lu/doc/misp/feed-osint/"


def fetch_manifest():
    print("Fetching CIRCL manifest...")

    response = requests.get(
        f"{CIRCL_URL}manifest.json",
        timeout=60
    )

    response.raise_for_status()

    manifest = response.json()

    if isinstance(manifest, dict):
        # Current CIRCL manifest maps event UUIDs to metadata.
        return list(manifest.keys())

    if isinstance(manifest, list):
        # Keep compatibility with older manifest format.
        return manifest

    raise RuntimeError(
        f"Unexpected CIRCL manifest format: {type(manifest).__name__}"
    )


def fetch_event(event_uuid):
    response = requests.get(
        f"{CIRCL_URL}{event_uuid}.json",
        timeout=60
    )

    response.raise_for_status()

    return response.json()


def main():
    print("=" * 60)
    print("CIRCL MISP INGESTION")
    print("=" * 60)

    manifest = fetch_manifest()

    print(f"Manifest contains {len(manifest)} events.")

    events = []
    indicators = []

    seen_events = set()
    seen_indicators = set()

    for index, event_uuid in enumerate(manifest, start=1):

        try:
            event_data = fetch_event(event_uuid)

            event = event_data.get("Event")

            if not event:
                print(
                    f"Skipping {event_uuid}: Event object missing."
                )
                continue

            normalized_event = normalize_misp_event(
                event,
                "CIRCL"
            )

            normalized_event["event_uuid"] = event_uuid

            if event_uuid not in seen_events:
                events.append(normalized_event)
                seen_events.add(event_uuid)

            # Extract top-level MISP attributes
            all_attributes = list(event.get("Attribute", []))

            # Extract attributes stored inside MISP Objects
            for obj in event.get("Object", []):
                 if isinstance(obj, dict):
                    all_attributes.extend(
                       obj.get("Attribute", [])
               )

            for attribute in all_attributes:

              indicator = normalize_misp_indicator(
                 attribute,
                 event_uuid,
                 "CIRCL"
              )

              value = indicator.get("value")
              indicator_type = indicator.get("type")

              if not value:
                  continue

              key = (
                 str(value).lower().strip(),
                 str(indicator_type).lower().strip(),
                 event_uuid
              )

              if key in seen_indicators:
                   continue

              seen_indicators.add(key)
              indicators.append(indicator)

            if index % 100 == 0:
                print(
                    f"Processed {index}/{len(manifest)} events..."
                )

        except Exception as error:
            print(
                f"Error processing {event_uuid}: {error}"
            )

    print("\nProcessing completed.")

    print(f"Prepared events: {len(events)}")
    print(f"Prepared indicators: {len(indicators)}")

    existing_events = events_collection.count_documents({
        "source": "CIRCL"
    })

    existing_indicators = indicators_collection.count_documents({
        "source": "CIRCL"
    })

    print(
        f"Existing CIRCL events: {existing_events}"
    )
    print(
        f"Existing CIRCL indicators: {existing_indicators}"
    )

    if existing_events > 0 or existing_indicators > 0:
        raise RuntimeError(
            "CIRCL data already exists. "
            "Aborting to prevent duplicate ingestion."
        )

    if events:
        print(f"\nInserting {len(events)} events...")

        events_collection.insert_many(
            events,
            ordered=False
        )

        print("Events inserted.")

    if indicators:
        print(
            f"Inserting {len(indicators)} indicators..."
        )

        indicators_collection.insert_many(
            indicators,
            ordered=False
        )

        print("Indicators inserted.")

    print("\nCreating CIRCL indexes...")

    events_collection.create_index("event_uuid")
    events_collection.create_index("source")
    events_collection.create_index("date")

    indicators_collection.create_index("event_uuid")
    indicators_collection.create_index("source")
    indicators_collection.create_index("value")
    indicators_collection.create_index("type")

    print("Indexes created.")

    final_events = events_collection.count_documents({
        "source": "CIRCL"
    })

    final_indicators = indicators_collection.count_documents({
        "source": "CIRCL"
    })

    print("\n" + "=" * 60)
    print("CIRCL VERIFICATION")
    print("=" * 60)

    print(f"CIRCL events:      {final_events}")
    print(f"CIRCL indicators:  {final_indicators}")

    print("\nCIRCL ingestion completed.")


if __name__ == "__main__":
    main()