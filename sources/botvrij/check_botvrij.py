import requests

BASE_URL = "https://www.botvrij.eu/data/feed-osint/"

manifest = requests.get(
    BASE_URL + "manifest.json",
    timeout=30
).json()

print("Total manifest entries:", len(manifest))

uuid = list(manifest.keys())[0]

print("\nTesting event:")
print(uuid)

event_url = BASE_URL + uuid + ".json"

response = requests.get(event_url, timeout=30)

print("\nStatus:", response.status_code)
print("Content-Type:", response.headers.get("Content-Type"))
print("Size:", len(response.content), "bytes")

response.raise_for_status()

event = response.json()

print("\nPython type:", type(event).__name__)
print("Top-level keys:", list(event.keys()))

if "Event" in event:
    e = event["Event"]

    print("\nEvent UUID:", e.get("uuid"))
    print("Event info:", e.get("info"))
    print("Event date:", e.get("date"))
    print("Threat level:", e.get("threat_level_id"))
    print("Attributes:", len(e.get("Attribute", [])))
    print("Tags:", len(e.get("Tag", [])))