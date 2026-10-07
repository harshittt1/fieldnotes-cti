import requests

BASE_URL = "https://www.circl.lu/doc/misp/feed-osint/"
MANIFEST_URL = BASE_URL + "manifest.json"

response = requests.get(MANIFEST_URL, timeout=60)

print("Status code:", response.status_code)
print("Content-Type:", response.headers.get("Content-Type"))
print("Response size:", len(response.content), "bytes")

response.raise_for_status()

manifest = response.json()

print("\nPython data type:", type(manifest))
print("Number of events:", len(manifest))

print("\nFirst 10 event UUIDs:")

for event_uuid in list(manifest.keys())[:10]:
    print(event_uuid)