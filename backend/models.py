from datetime import datetime, timezone


# ============================================================
# COMMON FIELDS
# ============================================================

def utc_now():
    """Return the current UTC time."""
    return datetime.now(timezone.utc)


# ============================================================
# MISP EVENT
# ============================================================

def normalize_misp_event(event, source):
    """
    Convert a raw MISP event into our common events schema.
    """

    return {
        "source": source,
        "sources": [source],
        "record_type": "misp_event",

        # Original MISP identity
        "event_uuid": event.get("uuid"),

        # Event metadata
        "info": event.get("info"),
        "date": event.get("date"),
        "threat_level": event.get("threat_level_id"),
        "analysis": event.get("analysis"),

        "published": event.get("published"),
        "publish_timestamp": event.get("publish_timestamp"),
        "timestamp": event.get("timestamp"),

        # MISP metadata
        "tags": event.get("Tag", []),

        # Number of original attributes
        "indicator_count": len(
            event.get("Attribute", [])
        ),

        # Ingestion metadata
        "ingested_at": utc_now()
    }


# ============================================================
# MISP INDICATOR
# ============================================================

def normalize_misp_indicator(attribute, event_uuid, source):
    """
    Convert one MISP Attribute into our indicators schema.
    """

    return {
        "source": source,
        "record_type": "misp_indicator",

        # Relationship to parent event
        "event_uuid": event_uuid,

        # Indicator information
        "value": attribute.get("value"),
        "type": attribute.get("type"),
        "category": attribute.get("category"),

        # MISP metadata
        "comment": attribute.get("comment"),
        "to_ids": attribute.get("to_ids"),
        "timestamp": attribute.get("timestamp"),

        # Original attribute ID
        "source_attribute_id": attribute.get("id"),

        "ingested_at": utc_now()
    }


# ============================================================
# THREATFOX
# ============================================================

def normalize_threatfox(record):
    """
    Convert one ThreatFox IOC into our common indicator schema.
    """

    return {
        "source": "ThreatFox",
        "record_type": "threatfox_ioc",

        "source_id": record.get("id"),

        "value": record.get("ioc"),
        "type": record.get("ioc_type"),
        "type_description": record.get("ioc_type_desc"),

        "threat_type": record.get("threat_type"),
        "threat_type_description": record.get(
            "threat_type_desc"
        ),

        "malware": record.get("malware"),
        "malware_printable": record.get(
            "malware_printable"
        ),

        "confidence": record.get(
            "confidence_level"
        ),

        "is_compromised": record.get(
            "is_compromised"
        ),

        "first_seen": record.get("first_seen"),
        "last_seen": record.get("last_seen"),

        "reference": record.get("reference"),
        "reporter": record.get("reporter"),
        "tags": record.get("tags", []),

        "ingested_at": utc_now()
    }


# ============================================================
# URLHAUS
# ============================================================

def normalize_urlhaus(record):
    """
    Convert one URLhaus record into our common indicator schema.
    """

    return {
        "source": "URLhaus",
        "record_type": "urlhaus_url",

        "value": record.get("url"),
        "type": "url",

        "url_status": record.get("url_status"),
        "threat": record.get("threat"),
        "tags": record.get("tags", []),

        "date_added": record.get("dateadded"),
        "last_online": record.get("last_online"),

        "reporter": record.get("reporter"),
        "urlhaus_link": record.get("urlhaus_link"),

        "ingested_at": utc_now()
    }


# ============================================================
# MALWAREBAZAAR
# ============================================================

def normalize_malwarebazaar(record):
    """
    Convert one MalwareBazaar sample into our malware schema.
    """

    return {
        "source": "MalwareBazaar",
        "record_type": "malware_sample",

        "sha256": record.get("sha256_hash"),
        "sha1": record.get("sha1_hash"),
        "md5": record.get("md5_hash"),

        "file_name": record.get("file_name"),
        "file_type": record.get("file_type"),
        "signature": record.get("signature"),

        "first_seen": record.get("first_seen"),
        "last_seen": record.get("last_seen"),

        "imphash": record.get("imphash"),
        "tlsh": record.get("tlsh"),

        "tags": record.get("tags", []),
        "intelligence": record.get(
            "intelligence",
            {}
        ),

        "ingested_at": utc_now()
    }


# ============================================================
# CTIDIGEST
# ============================================================

def normalize_ctidigest(record):
    """
    Convert one CTIDigest IOC into our CTIDigest collection schema.
    """

    return {
        "source": "CTIDigest",
        "record_type": "ctidigest_ioc",

        "value": record.get("value"),
        "type": record.get("type"),

        "source_name": record.get("source"),

        "confidence": record.get(
            "confidence"
        ),

        "category": record.get(
            "category"
        ),

        "description": record.get(
            "description"
        ),

        "first_seen": record.get(
            "first_seen"
        ),

        "ingested_at": utc_now()
    }
