import requests
from bson import BSON

BASE_URL = "https://www.circl.lu/doc/misp/feed-osint/"
MANIFEST_URL = BASE_URL + "manifest.json"

response = requests.get(MANIFEST_URL, timeout=60)
response.raise_for_status()

manifest = response.json()

event_uuids = list(manifest.keys())[:10]

attribute_sizes = []
total_attributes = 0

print("Inspecting MISP attributes from 10 real events...\n")

for event_uuid in event_uuids:

    url = BASE_URL + event_uuid + ".json"

    response = requests.get(url, timeout=60)
    response.raise_for_status()

    event_data = response.json()
    event = event_data.get("Event", event_data)

    attributes = event.get("Attribute", [])

    total_attributes += len(attributes)

    for attribute in attributes:
        size = len(BSON.encode(attribute))
        attribute_sizes.append(size)

print("Total attributes:", total_attributes)

print("\nBSON size of MISP attributes:")
print("Average:", round(sum(attribute_sizes) / len(attribute_sizes), 2), "bytes")
print("Average:", round(sum(attribute_sizes) / len(attribute_sizes) / 1024, 2), "KB")
print("Smallest:", min(attribute_sizes), "bytes")
print("Largest:", max(attribute_sizes), "bytes")

print("\nFirst attribute:")
print(attributes[0])