import os
import requests
from bson import BSON
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("THREATFOX_API_KEY")

if not API_KEY:
    raise ValueError("THREATFOX_API_KEY is missing from .env")

URL = "https://threatfox-api.abuse.ch/api/v1/"

headers = {
    "Auth-Key": API_KEY,
    "Content-Type": "application/json"
}

payload = {
    "query": "get_iocs",
    "days": 7
}

response = requests.post(
    URL,
    headers=headers,
    data=payload,
    timeout=60
)

response.raise_for_status()

result = response.json()
records = result.get("data", [])

print("Total records:", len(records))

sizes = []

for record in records:
    sizes.append(len(BSON.encode(record)))

average = sum(sizes) / len(sizes)

print("First document BSON size:", sizes[0], "bytes")
print("Average BSON size:", round(average, 2), "bytes")
print("Average BSON size:", round(average / 1024, 2), "KB")
print("Smallest:", min(sizes), "bytes")
print("Largest:", max(sizes), "bytes")