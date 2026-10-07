import os
import re
import requests
from dotenv import load_dotenv


# ============================================================
# SETUP
# ============================================================

load_dotenv()

THREATFOX_API_KEY = os.getenv("THREATFOX_API_KEY")
MALWAREBAZAAR_API_KEY = os.getenv("MALWAREBAZAAR_API_KEY")
URLHAUS_API_KEY = os.getenv("URLHAUS_API_KEY")

THREATFOX_API = "https://threatfox-api.abuse.ch/api/v1/"
MALWAREBAZAAR_API = "https://mb-api.abuse.ch/api/v1/"

CIRCL_MANIFEST = (
    "https://www.circl.lu/doc/misp/feed-osint/manifest.json"
)

BOTVRIJ_MANIFEST = (
    "https://www.botvrij.eu/data/feed-osint/manifest.json"
)

ROSTI_DIRECTORY = "https://misp.rosti.dev/"

CTIDIGEST_URL = "https://ctidigest.com/iocs.json"


# ============================================================
# BASIC VALIDATION
# ============================================================

if not THREATFOX_API_KEY:
    raise ValueError("THREATFOX_API_KEY is missing from .env")

if not MALWAREBAZAAR_API_KEY:
    raise ValueError("MALWAREBAZAAR_API_KEY is missing from .env")

if not URLHAUS_API_KEY:
    raise ValueError("URLHAUS_API_KEY is missing from .env")


# ============================================================
# HELPER
# ============================================================

def normalize(value):
    """
    Normalize IOC/hash values for comparison.
    """
    if value is None:
        return ""

    return str(value).strip().lower()


def get_json(url, **kwargs):
    """
    GET JSON with error handling.
    """
    response = requests.get(
        url,
        timeout=120,
        **kwargs
    )

    response.raise_for_status()

    return response.json()


# ============================================================
# 1. MISP EVENT DUPLICATION
# ============================================================

print("\n" + "=" * 60)
print("1. MISP EVENT DUPLICATION")
print("=" * 60)


# ------------------------------------------------------------
# CIRCL
# ------------------------------------------------------------

print("\nFetching CIRCL manifest...")

circl_manifest = get_json(CIRCL_MANIFEST)

if not isinstance(circl_manifest, dict):
    raise ValueError("CIRCL manifest is not a dictionary")

circl_uuids = set(circl_manifest.keys())

print("CIRCL:", len(circl_uuids))


# ------------------------------------------------------------
# BOTVRIJ
# ------------------------------------------------------------

print("\nFetching Botvrij manifest...")

botvrij_manifest = get_json(BOTVRIJ_MANIFEST)

if not isinstance(botvrij_manifest, dict):
    raise ValueError("Botvrij manifest is not a dictionary")

botvrij_uuids = set(botvrij_manifest.keys())

print("Botvrij:", len(botvrij_uuids))


# ------------------------------------------------------------
# ROSTI
# ------------------------------------------------------------

print("\nFetching Rösti directory...")

response = requests.get(
    ROSTI_DIRECTORY,
    timeout=120
)

response.raise_for_status()

html = response.text

# Find JSON filenames from directory listing
rosti_files = set(
    re.findall(
        r'href=["\']([^"\']+\.json)["\']',
        html,
        flags=re.IGNORECASE
    )
)

# Keep only UUID-named JSON files.
# This excludes manifest.json.
uuid_pattern = re.compile(
    r"^[0-9a-fA-F]{8}-"
    r"[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{12}\.json$"
)

rosti_files = {
    filename
    for filename in rosti_files
    if uuid_pattern.match(filename)
}

rosti_uuids = {
    filename[:-5]
    for filename in rosti_files
}

print("Rösti:", len(rosti_uuids))


# ------------------------------------------------------------
# MISP DEDUPLICATION
# ------------------------------------------------------------

all_misp_events = (
    circl_uuids
    | botvrij_uuids
    | rosti_uuids
)

circl_botvrij_overlap = (
    circl_uuids & botvrij_uuids
)

circl_rosti_overlap = (
    circl_uuids & rosti_uuids
)

botvrij_rosti_overlap = (
    botvrij_uuids & rosti_uuids
)

all_three_overlap = (
    circl_uuids
    & botvrij_uuids
    & rosti_uuids
)

raw_misp_total = (
    len(circl_uuids)
    + len(botvrij_uuids)
    + len(rosti_uuids)
)


print("\nMISP RESULTS")
print("-" * 35)

print("CIRCL:", len(circl_uuids))
print("Botvrij:", len(botvrij_uuids))
print("Rösti:", len(rosti_uuids))

print("Raw MISP total:", raw_misp_total)
print("Unique MISP events:", len(all_misp_events))

print("\nMISP overlaps:")
print(
    "CIRCL <-> Botvrij:",
    len(circl_botvrij_overlap)
)

print(
    "CIRCL <-> Rösti:",
    len(circl_rosti_overlap)
)

print(
    "Botvrij <-> Rösti:",
    len(botvrij_rosti_overlap)
)

print(
    "All three:",
    len(all_three_overlap)
)


# ============================================================
# 2. THREATFOX
# ============================================================

print("\n" + "=" * 60)
print("2. THREATFOX")
print("=" * 60)


threatfox_headers = {
    "Auth-Key": THREATFOX_API_KEY,
    "Content-Type": "application/json"
}

threatfox_payload = {
    "query": "get_iocs",
    "days": 7
}


# IMPORTANT:
# ThreatFox expects JSON.
# Therefore use json=payload, NOT data=payload.

response = requests.post(
    THREATFOX_API,
    headers=threatfox_headers,
    json=threatfox_payload,
    timeout=120
)

response.raise_for_status()

threatfox_result = response.json()

print(
    "ThreatFox query status:",
    threatfox_result.get("query_status")
)

if threatfox_result.get("query_status") != "ok":
    raise ValueError(
        "ThreatFox request failed: "
        + str(threatfox_result)
    )

threatfox_records = threatfox_result.get(
    "data",
    []
)

if not isinstance(threatfox_records, list):
    raise ValueError(
        "ThreatFox data is not a list: "
        + str(type(threatfox_records))
    )

print(
    "ThreatFox records:",
    len(threatfox_records)
)


# ------------------------------------------------------------
# ThreatFox IOC duplicates
# ------------------------------------------------------------

threatfox_iocs = []

for record in threatfox_records:

    if not isinstance(record, dict):
        continue

    ioc = normalize(
        record.get("ioc")
    )

    if ioc:
        threatfox_iocs.append(ioc)


threatfox_ioc_set = set(threatfox_iocs)

print(
    "ThreatFox unique IOCs:",
    len(threatfox_ioc_set)
)

print(
    "ThreatFox duplicate IOCs:",
    len(threatfox_iocs)
    - len(threatfox_ioc_set)
)


# ============================================================
# 3. URLHAUS
# ============================================================

print("\n" + "=" * 60)
print("3. URLHAUS")
print("=" * 60)


urlhaus_url = (
    "https://urlhaus-api.abuse.ch/v2/files/exports/"
    + URLHAUS_API_KEY
    + "/recent.json"
)

response = requests.get(
    urlhaus_url,
    timeout=120
)

response.raise_for_status()

urlhaus_data = response.json()

if not isinstance(urlhaus_data, dict):
    raise ValueError(
        "URLhaus response is not a dictionary"
    )


# URLhaus recent.json has lists as dictionary values.
urlhaus_records = []

for value in urlhaus_data.values():

    if isinstance(value, list):

        for record in value:

            if isinstance(record, dict):
                urlhaus_records.append(record)


print(
    "URLhaus records:",
    len(urlhaus_records)
)


# ------------------------------------------------------------
# URLhaus URL duplicates
# ------------------------------------------------------------

urlhaus_urls = []

for record in urlhaus_records:

    url = normalize(
        record.get("url")
    )

    if url:
        urlhaus_urls.append(url)


urlhaus_url_set = set(urlhaus_urls)

print(
    "URLhaus unique URLs:",
    len(urlhaus_url_set)
)

print(
    "URLhaus duplicate URLs:",
    len(urlhaus_urls)
    - len(urlhaus_url_set)
)


# ============================================================
# 4. MALWAREBAZAAR
# ============================================================

print("\n" + "=" * 60)
print("4. MALWAREBAZAAR")
print("=" * 60)


malware_headers = {
    "Auth-Key": MALWAREBAZAAR_API_KEY
}

malware_payload = {
    "query": "recent_detections",
    "hours": "168"
}


# IMPORTANT:
# MalwareBazaar expects form data.
# Therefore use data=payload.

response = requests.post(
    MALWAREBAZAAR_API,
    headers=malware_headers,
    data=malware_payload,
    timeout=120
)

response.raise_for_status()

malware_result = response.json()

print(
    "MalwareBazaar query status:",
    malware_result.get("query_status")
)

malware_records = malware_result.get(
    "data",
    []
)

if not isinstance(malware_records, list):
    raise ValueError(
        "MalwareBazaar data is not a list: "
        + str(type(malware_records))
    )

print(
    "MalwareBazaar records:",
    len(malware_records)
)


# ------------------------------------------------------------
# MalwareBazaar hashes
# ------------------------------------------------------------

malware_sha256 = set()
malware_sha1 = set()
malware_md5 = set()


for record in malware_records:

    if not isinstance(record, dict):
        continue

    sha256 = normalize(
        record.get("sha256_hash")
        or record.get("sha256")
    )

    sha1 = normalize(
        record.get("sha1_hash")
        or record.get("sha1")
    )

    md5 = normalize(
        record.get("md5_hash")
        or record.get("md5")
    )

    if sha256:
        malware_sha256.add(sha256)

    if sha1:
        malware_sha1.add(sha1)

    if md5:
        malware_md5.add(md5)


print(
    "Unique SHA256:",
    len(malware_sha256)
)

print(
    "Unique SHA1:",
    len(malware_sha1)
)

print(
    "Unique MD5:",
    len(malware_md5)
)


# ============================================================
# 5. CTIDIGEST
# ============================================================

print("\n" + "=" * 60)
print("5. CTIDIGEST")
print("=" * 60)


ctidigest_data = get_json(
    CTIDIGEST_URL
)

if not isinstance(ctidigest_data, list):
    raise ValueError(
        "CTIDigest response is not a list"
    )

ctidigest_records = ctidigest_data

print(
    "CTIDigest records:",
    len(ctidigest_records)
)


# ------------------------------------------------------------
# CTIDigest IOC duplicates
# ------------------------------------------------------------

ctidigest_values = []

for record in ctidigest_records:

    if not isinstance(record, dict):
        continue

    value = normalize(
        record.get("value")
    )

    if value:
        ctidigest_values.append(value)


ctidigest_value_set = set(
    ctidigest_values
)

print(
    "CTIDigest unique values:",
    len(ctidigest_value_set)
)

print(
    "CTIDigest duplicate values:",
    len(ctidigest_values)
    - len(ctidigest_value_set)
)


# ============================================================
# 6. CROSS-SOURCE IOC OVERLAPS
# ============================================================

print("\n" + "=" * 60)
print("6. CROSS-SOURCE IOC OVERLAPS")
print("=" * 60)


# ------------------------------------------------------------
# ThreatFox <-> URLhaus
# ------------------------------------------------------------

threatfox_urlhaus_overlap = (
    threatfox_ioc_set
    & urlhaus_url_set
)

print(
    "ThreatFox <-> URLhaus:",
    len(threatfox_urlhaus_overlap)
)


# ------------------------------------------------------------
# ThreatFox <-> CTIDigest
# ------------------------------------------------------------

threatfox_ctidigest_overlap = (
    threatfox_ioc_set
    & ctidigest_value_set
)

print(
    "ThreatFox <-> CTIDigest:",
    len(threatfox_ctidigest_overlap)
)


# ------------------------------------------------------------
# URLhaus <-> CTIDigest
# ------------------------------------------------------------

urlhaus_ctidigest_overlap = (
    urlhaus_url_set
    & ctidigest_value_set
)

print(
    "URLhaus <-> CTIDigest:",
    len(urlhaus_ctidigest_overlap)
)


# ============================================================
# 7. MALWAREBAZAAR HASH OVERLAPS
# ============================================================

print("\n" + "=" * 60)
print("7. MALWAREBAZAAR HASH OVERLAPS")
print("=" * 60)


# ------------------------------------------------------------
# Combine ThreatFox + CTIDigest values
# ------------------------------------------------------------

threatfox_and_ctidigest = (
    threatfox_ioc_set
    | ctidigest_value_set
)


# ------------------------------------------------------------
# SHA256 overlap
# ------------------------------------------------------------

sha256_overlap = (
    malware_sha256
    & threatfox_and_ctidigest
)

print(
    "MalwareBazaar SHA256 <-> ThreatFox/CTIDigest:",
    len(sha256_overlap)
)


# ------------------------------------------------------------
# SHA1 overlap
# ------------------------------------------------------------

sha1_overlap = (
    malware_sha1
    & threatfox_and_ctidigest
)

print(
    "MalwareBazaar SHA1 <-> ThreatFox/CTIDigest:",
    len(sha1_overlap)
)


# ------------------------------------------------------------
# MD5 overlap
# ------------------------------------------------------------

md5_overlap = (
    malware_md5
    & threatfox_and_ctidigest
)

print(
    "MalwareBazaar MD5 <-> ThreatFox/CTIDigest:",
    len(md5_overlap)
)


# ============================================================
# 8. FINAL SUMMARY
# ============================================================

print("\n" + "=" * 60)
print("FINAL SUMMARY")
print("=" * 60)


# ------------------------------------------------------------
# MISP
# ------------------------------------------------------------

print("\nMISP EVENTS")
print("-" * 35)

print(
    "CIRCL:",
    len(circl_uuids)
)

print(
    "Botvrij:",
    len(botvrij_uuids)
)

print(
    "Rösti:",
    len(rosti_uuids)
)

print(
    "Raw MISP total:",
    raw_misp_total
)

print(
    "Unique MISP events:",
    len(all_misp_events)
)


# ------------------------------------------------------------
# Other CTI sources
# ------------------------------------------------------------

print("\nCTI RECORDS")
print("-" * 35)

print(
    "ThreatFox:",
    len(threatfox_records)
)

print(
    "URLhaus:",
    len(urlhaus_records)
)

print(
    "MalwareBazaar:",
    len(malware_records)
)

print(
    "CTIDigest:",
    len(ctidigest_records)
)


# ------------------------------------------------------------
# Combined raw count
# ------------------------------------------------------------

core_raw_total = (
    len(all_misp_events)
    + len(threatfox_records)
    + len(urlhaus_records)
    + len(malware_records)
)

with_ctidigest_total = (
    core_raw_total
    + len(ctidigest_records)
)


print("\nTOTALS")
print("-" * 35)

print(
    "Core unique MISP + CTI raw records:",
    core_raw_total
)

print(
    "Including CTIDigest:",
    with_ctidigest_total
)


# ------------------------------------------------------------
# Important note
# ------------------------------------------------------------

print("\nNOTE")
print("-" * 35)

print(
    "These are live-source snapshots. "
    "Counts can change between runs."
)

print(
    "No MongoDB data was inserted or modified."
)

print(
    "No synthetic or generated records were created."
)

print("\nDeduplication analysis completed.")