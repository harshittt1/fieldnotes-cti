import requests
import re

BASE_URL = "https://misp.rosti.dev/"

response = requests.get(BASE_URL, timeout=30)
response.raise_for_status()

files = re.findall(r'href="([^"]+\.json)"', response.text)

uuid_pattern = re.compile(
    r"^[0-9a-fA-F]{8}-"
    r"[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{12}\.json$"
)

non_uuid = [
    filename
    for filename in files
    if not uuid_pattern.fullmatch(filename)
]

print("Total JSON files:", len(files))
print("Non-UUID JSON files:", len(non_uuid))

for filename in non_uuid:
    print(filename)