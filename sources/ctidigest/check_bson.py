import requests
from bson import BSON

URL = "https://ctidigest.com/iocs.json"

response = requests.get(URL, timeout=60)
response.raise_for_status()

data = response.json()

print("Total records:", len(data))

sizes = []

for record in data[:100]:
    size = len(BSON.encode(record))
    sizes.append(size)

average_size = sum(sizes) / len(sizes)

print("First document BSON size:", sizes[0], "bytes")
print("Average BSON size of first 100:", round(average_size, 2), "bytes")
print("Smallest:", min(sizes), "bytes")
print("Largest:", max(sizes), "bytes")