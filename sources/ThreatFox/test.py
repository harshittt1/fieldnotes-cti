import os
import json
import requests
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
    data=json.dumps(payload),
    timeout=60
)

print("Status code:", response.status_code)
print("Content-Type:", response.headers.get("Content-Type"))
print("Response size:", len(response.content), "bytes")

print("\nResponse:")
print(response.text[:1000])

response.raise_for_status()

result = response.json()

print("\nQuery status:", result.get("query_status"))

records = result.get("data", [])

print("Number of records:", len(records))

if records:
    print("\nFirst record:")
    print(records[0])

    print("\nLast record:")
    print(records[-1])