import requests
import re

CIRCL_URL = "https://www.circl.lu/doc/misp/feed-osint/manifest.json"
BOTVRIJ_URL = "https://www.botvrij.eu/data/feed-osint/manifest.json"
ROSTI_URL = "https://misp.rosti.dev/"

# -----------------------------
# CIRCL
# -----------------------------
print("Fetching CIRCL manifest...")

circl_manifest = requests.get(
    CIRCL_URL,
    timeout=30
).json()

circl_ids = set(circl_manifest.keys())

print("CIRCL events:", len(circl_ids))


# -----------------------------
# Botvrij
# -----------------------------
print("\nFetching Botvrij manifest...")

botvrij_manifest = requests.get(
    BOTVRIJ_URL,
    timeout=30
).json()

botvrij_ids = set(botvrij_manifest.keys())

print("Botvrij events:", len(botvrij_ids))


# -----------------------------
# Rösti
# -----------------------------
print("\nFetching Rösti directory...")

rosti_response = requests.get(
    ROSTI_URL,
    timeout=30
)

rosti_response.raise_for_status()

rosti_files = re.findall(
    r'href="([^"]+\.json)"',
    rosti_response.text
)

rosti_ids = set()

for filename in rosti_files:
    uuid = filename.replace(".json", "")

    # Ignore anything that isn't UUID-shaped
    if re.fullmatch(
        r"[0-9a-fA-F]{8}-"
        r"[0-9a-fA-F]{4}-"
        r"[0-9a-fA-F]{4}-"
        r"[0-9a-fA-F]{4}-"
        r"[0-9a-fA-F]{12}",
        uuid
    ):
        rosti_ids.add(uuid)

print("Rösti events:", len(rosti_ids))


# -----------------------------
# Deduplication
# -----------------------------
all_ids = circl_ids | botvrij_ids | rosti_ids

print("\n==============================")
print("RESULT")
print("==============================")

print("CIRCL:", len(circl_ids))
print("Botvrij:", len(botvrij_ids))
print("Rösti:", len(rosti_ids))

print("\nRaw total:")
print(len(circl_ids) + len(botvrij_ids) + len(rosti_ids))

print("\nUnique MISP events:")
print(len(all_ids))


# -----------------------------
# Overlap analysis
# -----------------------------
print("\n==============================")
print("OVERLAPS")
print("==============================")

circl_botvrij = circl_ids & botvrij_ids
circl_rosti = circl_ids & rosti_ids
botvrij_rosti = botvrij_ids & rosti_ids

print("CIRCL ∩ Botvrij:", len(circl_botvrij))
print("CIRCL ∩ Rösti:", len(circl_rosti))
print("Botvrij ∩ Rösti:", len(botvrij_rosti))

triple_overlap = circl_ids & botvrij_ids & rosti_ids

print("All 3 sources:", len(triple_overlap))