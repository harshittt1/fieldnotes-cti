"""Retired script: the old version fabricated events to inflate the count to 120k.

ThreatFox, URLhaus, MalwareBazaar, and CTIDigest are feed data, not MISP events.
Use the source-specific ingestion modules to write them to their own collections.
This file intentionally performs no database or network operations.
"""

raise SystemExit(
    "Disabled: this legacy script generated synthetic event records. "
    "Ingest feed data through the source-specific ingestion modules instead."
)
