import os
import requests
from dotenv import load_dotenv
from bson import BSON

load_dotenv()

API_KEY = os.getenv("MALWAREBAZAAR_API_KEY")

if not API_KEY:
    raise ValueError("MALWAREBAZAAR_API_KEY is missing from .env")

URL = (
    "https://urlhaus-api.abuse.ch/"
    "v2/files/exports/"
    f"{API_KEY}/recent.json"
)

response = requests.get(URL, timeout=120)

print("Status code:", response.status_code)
print("Content-Type:", response.headers.get("Content-Type"))
print("Response size:", len(response.content), "bytes")

response.raise_for_status()

data = response.json()

records = []

for key, value in data.items():
    if isinstance(value, list):
        for item in value:
            if isinstance(item, dict):
                records.append(item)
    elif isinstance(value, dict):
        records.append(value)

print("Actual URL records:", len(records))

# BSON size analysis
sizes = [len(BSON.encode(record)) for record in records[:100]]

print("\nBSON size analysis for first 100 records:")
print("Average:", sum(sizes) / len(sizes), "bytes")
print("Average:", sum(sizes) / len(sizes) / 1024, "KB")
print("Smallest:", min(sizes), "bytes")
print("Largest:", max(sizes), "bytes")

print("\nFirst record:")
print(records[0])