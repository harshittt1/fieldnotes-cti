"""Retired script: its old version inserted synthetic feed rows into events.

ThreatFox, URLhaus, MalwareBazaar, and CTIDigest records belong in their own
indicator/feed collections. This file intentionally performs no writes.
"""

raise SystemExit(
    "Disabled: use ingestion/threatfox.py, ingestion/urlhaus.py, "
    "ingestion/malwarebazaar.py, or ingestion/ctidigest.py."
)
