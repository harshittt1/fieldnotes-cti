import requests
import re

BASE_URL = "https://misp.rosti.dev/"

response = requests.get(BASE_URL, timeout=30)
response.raise_for_status()

files = re.findall(r'href="([^"]+\.json)"', response.text)

print("Total JSON files:", len(files))
print("\nChecking first 10 events...\n")

valid = 0

for filename in files[:10]:

    url = BASE_URL + filename

    try:
        r = requests.get(url, timeout=30)
        r.raise_for_status()

        data = r.json()

        if "Event" in data:

            event = data["Event"]

            print("✓", filename)
            print("  UUID:", event.get("uuid"))
            print("  Info:", event.get("info"))
            print("  Attributes:", len(event.get("Attribute", [])))
            print()

            valid += 1

        else:
            print("✗", filename, "- No Event object")

    except Exception as e:
        print("✗", filename, "-", e)

print("================================")
print("Valid MISP events:", valid, "/ 10")