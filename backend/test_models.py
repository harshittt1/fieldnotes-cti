from backend.models import (
    normalize_threatfox,
    normalize_urlhaus,
    normalize_malwarebazaar,
    normalize_ctidigest
)


# ------------------------------------------------------------
# ThreatFox test
# ------------------------------------------------------------

threatfox_sample = {
    "id": "123",
    "ioc": "1.2.3.4",
    "ioc_type": "ip:port",
    "ioc_type_desc": "IP address",
    "threat_type": "botnet_cc",
    "threat_type_desc": "Botnet C&C",
    "malware": "Example",
    "malware_printable": "Example",
    "confidence_level": 95,
    "first_seen": "2026-10-01",
    "last_seen": None,
    "reference": "https://example.com",
    "reporter": "test",
    "tags": []
}

print("\nThreatFox:")
print(normalize_threatfox(threatfox_sample))


# ------------------------------------------------------------
# URLhaus test
# ------------------------------------------------------------

urlhaus_sample = {
    "url": "http://example.com/test",
    "url_status": "online",
    "threat": "malware_download",
    "tags": ["test"],
    "dateadded": "2026-10-01",
    "last_online": "2026-10-02",
    "reporter": "test",
    "urlhaus_link": "https://urlhaus.abuse.ch/"
}

print("\nURLhaus:")
print(normalize_urlhaus(urlhaus_sample))


# ------------------------------------------------------------
# MalwareBazaar test
# ------------------------------------------------------------

malware_sample = {
    "sha256_hash": "a" * 64,
    "sha1_hash": "b" * 40,
    "md5_hash": "c" * 32,
    "file_name": "sample.exe",
    "file_type": "exe",
    "signature": "Example",
    "first_seen": "2026-10-01",
    "last_seen": None,
    "imphash": None,
    "tlsh": None,
    "tags": [],
    "intelligence": {}
}

print("\nMalwareBazaar:")
print(normalize_malwarebazaar(malware_sample))


# ------------------------------------------------------------
# CTIDigest test
# ------------------------------------------------------------

ctidigest_sample = {
    "value": "1.2.3.4",
    "type": "ip",
    "source": "IPsum",
    "confidence": 95,
    "category": "threat-actors",
    "description": "Blacklist score: 9",
    "first_seen": "2026-10-01"
}

print("\nCTIDigest:")
print(normalize_ctidigest(ctidigest_sample))


print("\nAll normalization tests completed.")