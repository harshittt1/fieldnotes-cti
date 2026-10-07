import requests

URL = "https://ctidigest.com/iocs.json"

response = requests.get(URL, timeout=60)

print("Status code:", response.status_code)
print("Content-Type:", response.headers.get("Content-Type"))
print("Size:", len(response.content), "bytes")

response.raise_for_status()

data = response.json()

print("Python data type:", type(data))

if isinstance(data, list):
    print("Number of records:", len(data))
    print("\nFirst record:")
    print(data[0])

elif isinstance(data, dict):
    print("Dictionary keys:")
    print(data.keys())

    for key, value in data.items():
        if isinstance(value, list):
            print(f"Possible record list: {key}")
            print("Number of records:", len(value))
            print("\nFirst record:")
            print(value[0])
            break