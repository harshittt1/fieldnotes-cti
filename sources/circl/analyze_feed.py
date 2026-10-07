import requests

BASE_URL = "https://www.circl.lu/doc/misp/feed-osint/"
MANIFEST_URL = BASE_URL + "manifest.json"

response = requests.get(MANIFEST_URL, timeout=60)
response.raise_for_status()

manifest = response.json()

event_uuids = list(manifest.keys())

total_events = len(event_uuids)
total_attributes = 0

print("Total events:", total_events)
print("Counting attributes...\n")

for index, event_uuid in enumerate(event_uuids, start=1):

    url = BASE_URL + event_uuid + ".json"

    response = requests.get(url, timeout=60)
    response.raise_for_status()

    data = response.json()

    event = data.get("Event", data)

    attributes = event.get("Attribute", [])

    total_attributes += len(attributes)

    if index % 100 == 0:
        print(
            f"Processed {index}/{total_events} events | "
            f"Attributes so far: {total_attributes}"
        )

print("\n" + "=" * 50)
print("FINAL RESULT")
print("=" * 50)

print("Total MISP events:", total_events)
print("Total MISP attributes:", total_attributes)