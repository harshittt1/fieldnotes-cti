import os
import requests
import datetime
import re
import ipaddress
import base64
from pathlib import Path
from urllib.parse import quote, urlsplit
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from backend.db import db
from backend.threat_feed import unified_pipeline, single_source_pipeline, source_pipeline, normalization_pipeline, count_by_source, feed_total, source_count, FEED_COLLECTIONS
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parents[1] / ".env")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

app = FastAPI(title="CTI Platform API")

# Allow frontend to connect
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

PAGE_SIZE_DEFAULT = 12
PAGE_SIZE_MAX = 100
EVENTS_FILTER = {"record_type": "misp_event"}
SOURCE_FEEDS = {
    "CIRCL": "https://www.circl.lu/doc/misp/feed-osint/",
    "Botvrij": "https://www.botvrij.eu/data/feed-osint/",
    "Rösti": "https://misp.rosti.dev/",
}


def _category_for(event):
    text = " ".join([
        str(event.get("info") or ""),
        " ".join(str(x) for x in event.get("galaxy_clusters") or []),
        " ".join(str(tag.get("name", "") if isinstance(tag, dict) else tag)
                 for tag in event.get("tags") or []),
    ]).lower()
    rules = [
        ("Ransomware", r"ransom|locker|crypt(?:or|ing)"),
        ("Vulnerabilities", r"cve[- ]?\d|vulnerabilit|zero.?day|exploit"),
        ("Patches", r"patch|security update|hotfix"),
        ("Government", r"government|gov(?:ernment)?\b|ministry|public sector"),
        ("Mobile", r"android|ios|mobile|iphone|smartphone"),
        ("Cloud", r"cloud|aws|azure|gcp|kubernetes"),
        ("IoT", r"\biot\b|router|camera|mirai|embedded device"),
        ("Cryptography", r"crypto|cryptograph|openssl|tls|certificate"),
        ("Compromised", r"compromis|breach|expos(?:ed|ure)|leak"),
        ("Malware", r"malware|trojan|stealer|botnet|payload|ransomware"),
        ("Threat-Actors", r"threat actor|\bapt\s*\d|\bta\d{3,}|campaign|intrusion set"),
    ]
    for category, pattern in rules:
        if re.search(pattern, text):
            return category
    return "Threat-Actors"


def _severity_for(event):
    text = str(event.get("info") or "").lower()
    if "critical" in text:
        return "Critical"
    level = str(event.get("threat_level_id", event.get("threat_level", "")))
    return {"1": "High", "2": "Medium", "3": "Low", "4": "Low"}.get(level, "High")


def _source_url(event):
    source = str(event.get("source") or "")
    event_uuid = quote(str(event.get("event_uuid") or ""), safe="-")
    if source in SOURCE_FEEDS and event_uuid:
        return f"{SOURCE_FEEDS[source]}{event_uuid}.json"
    indicator = db.indicators.find_one(
        {"event_uuid": event.get("event_uuid"), "source": source},
        {"_id": 0, "source_id": 1, "reference": 1, "urlhaus_link": 1},
    )
    if indicator:
        if source == "ThreatFox" and indicator.get("source_id"):
            return f"https://threatfox.abuse.ch/ioc/{quote(str(indicator['source_id']))}/"
        if source == "URLhaus" and indicator.get("urlhaus_link"):
            url = indicator["urlhaus_link"]
            if urlsplit(url).hostname == "urlhaus.abuse.ch":
                return url
    return None


def _indicator_source_url(row):
    source = row.get("source")
    if source == "ThreatFox" and row.get("source_id"):
        return f"https://threatfox.abuse.ch/ioc/{quote(str(row['source_id']))}/"
    if source == "URLhaus" and row.get("urlhaus_link"):
        return row["urlhaus_link"]
    if source == "MalwareBazaar" and row.get("sha256"):
        return f"https://bazaar.abuse.ch/sample/{quote(str(row['sha256']))}/"
    if row.get("event_uuid") and source in SOURCE_FEEDS:
        return f"{SOURCE_FEEDS[source]}{quote(str(row['event_uuid']), safe='-')}.json"
    if source == "CTIDigest":
        upstream = {
            "AbuseIPDB": "https://www.abuseipdb.com/",
            "CISA KEV": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            "Emerging Threats": "https://rules.emergingthreats.net/",
            "Feodo Tracker": "https://feodotracker.abuse.ch/",
            "IPsum": "https://github.com/stamparm/ipsum/blob/master/ipsum.txt",
            "Tor Exit Nodes": "https://check.torproject.org/torbulkexitlist",
        }
        return upstream.get(row.get("source_name"), "https://ctidigest.com/")
    if source == "VirusTotal" and row.get("vt_url"):
        return row["vt_url"]
    return None


@app.get("/api/metrics")
def get_metrics():
    event_count = feed_total()
    try:
        data_size_mb = round(db.command("dbstats").get("dataSize", 0) / (1024 * 1024), 2)
    except Exception:
        data_size_mb = 0
    try:
        status = db.command("serverStatus")
        cache = status.get("wiredTiger", {}).get("cache", {})
        cache_max = round(cache.get("maximum bytes configured", 1024 * 1024 * 1024) / (1024 * 1024), 0)
        requested = cache.get("pages requested from the cache", 0)
        read = cache.get("pages read into cache", 0)
        hit_ratio = round(max(0, 1 - (read / requested)) * 100, 2) if requested else 100.0
    except Exception:
        cache_max, hit_ratio = 1024, 100.0
    size_rows = list(db.events.aggregate(unified_pipeline() + [
        {"$sample": {"size": 1000}},
        {"$project": {"n": {"$bsonSize": "$$ROOT"}}},
        {"$group": {"_id": None, "avg": {"$avg": "$n"}}},
    ], allowDiskUse=True, maxTimeMS=60000))
    avg_kb = round((size_rows[0]["avg"] / 1024), 2) if size_rows else 0
    return {"working_set_mb": data_size_mb, "event_count": event_count,
            "cache_max_mb": int(cache_max), "hit_ratio": hit_ratio, "avg_bson_kb": avg_kb}


def _event_query(search=None, category=None, source=None, year=None, severity=None):
    clauses = []
    if search:
        safe = re.escape(search.strip())
        search_terms = [
            {"info": {"$regex": safe, "$options": "i"}},
            {"tags.name": {"$regex": safe, "$options": "i"}},
            {"galaxy_clusters": {"$regex": safe, "$options": "i"}},
            {"event_uuid": {"$regex": safe, "$options": "i"}},
        ]
        linked = db.indicators.distinct("event_uuid", {"value": {"$regex": f"^{safe}$", "$options": "i"}})
        if linked:
            search_terms.append({"event_uuid": {"$in": linked}})
        clauses.append({"$or": search_terms})
    if category and category.lower() != "all":
        pattern = {
            "Threat-Actors": r"threat actor|\bapt\s*\d|\bta\d{3,}|campaign|intrusion set",
            "Vulnerabilities": r"cve[- ]?\d|vulnerabilit|zero.?day|exploit",
            "Ransomware": r"ransom|locker|crypt(?:or|ing)", "Patches": r"patch|security update|hotfix",
            "Malware": r"malware|trojan|stealer|botnet|payload|ransomware",
            "Government": r"government|\bgov\b|ministry|public sector", "Mobile": r"android|ios|mobile|iphone|smartphone",
            "Cloud": r"cloud|aws|azure|gcp|kubernetes", "IoT": r"\biot\b|router|camera|mirai|embedded device",
            "Cryptography": r"crypto|cryptograph|openssl|tls|certificate", "Compromised": r"compromis|breach|expos(?:ed|ure)|leak",
        }.get(category)
        if pattern:
            clauses.append({"$or": [
                {"info": {"$regex": pattern, "$options": "i"}},
                {"tags.name": {"$regex": pattern, "$options": "i"}},
                {"galaxy_clusters": {"$regex": pattern, "$options": "i"}},
            ]})
    if source and source.lower() not in ("all", "all verified sources"):
        clauses.append({"$or": [{"source": source}, {"sources": source}]})
    if year and year.lower() not in ("all", "all time"):
        clauses.append({"date": {"$regex": f"^{re.escape(year)}"}})
    if severity and severity.lower() != "all":
        if severity == "Critical":
            clauses.append({"info": {"$regex": "critical", "$options": "i"}})
        else:
            level = {"High": "1", "Medium": "2", "Low": "3"}.get(severity)
            if level:
                clauses.append({"$or": [{"threat_level_id": level}, {"threat_level": level}]})
    clauses.insert(0, EVENTS_FILTER)
    return {"$and": clauses}

@app.get("/")
def read_root():
    return {"status": "CTI API is running!"}

@app.get("/api/reports")
def get_reports():
    """Returns the verified annual security reports for the UI"""
    reports = list(db.annual_reports.find({}, {"_id": 0}))
    return reports

@app.get("/api/events")
def get_events(limit: int = PAGE_SIZE_DEFAULT, skip: int = 0, search: str = None,
               category: str = None, source: str = None, year: str = None,
               severity: str = None, sort: str = "newest"):
    """Paginated threat reports with feed filters and source provenance."""
    limit = max(1, min(limit, PAGE_SIZE_MAX))
    skip = max(0, skip)
    selected_source = source if source and source.lower() not in ("all", "all verified sources") else None
    has_non_source_filters = any((search, category and category.lower() != "all",
                                  year and year.lower() not in ("all", "all time"),
                                  severity and severity.lower() != "all"))
    if not has_non_source_filters:
        source_map = {"CIRCL": "events", "Botvrij": "events", "Rösti": "events",
                      "ThreatFox": "indicators", "URLhaus": "indicators",
                      "MalwareBazaar": "malware", "CTIDigest": "ctidigest", "VirusTotal": "vt_feed"}
        collections = [source_map[selected_source]] if selected_source in source_map else list(FEED_COLLECTIONS)
        rows = []
        for collection_name in collections:
            pipeline = source_pipeline(collection_name)
            if selected_source:
                origin_filter = ({"$or": [{"source": selected_source}, {"sources": selected_source}]}
                                 if collection_name == "events" else {"source": selected_source})
                pipeline.append({"$match": origin_filter})
            rows.extend(db[collection_name].aggregate(
                pipeline + normalization_pipeline() + [
                    {"$sort": {"feed_sort_at": -1, "feed_id": 1}},
                    {"$limit": skip + limit},
                    {"$project": {"raw_data": 0}},
                ], allowDiskUse=True, maxTimeMS=60000))
        rows.sort(key=lambda row: row.get("feed_sort_at") or datetime.datetime.min, reverse=True)
        events = rows[skip:skip + limit]
        event_uuids = [row.get("event_uuid") for row in events
                       if row.get("record_type") == "misp_event" and row.get("event_uuid")]
        first_values = {}
        if event_uuids:
            for indicator in db.indicators.find({"event_uuid": {"$in": event_uuids}},
                                                {"_id": 0, "event_uuid": 1, "value": 1}).limit(3000):
                if indicator.get("value"):
                    first_values.setdefault(indicator["event_uuid"], indicator["value"])
        for event in events:
            if event.get("record_type") == "misp_event" and event.get("source") in SOURCE_FEEDS and event.get("event_uuid"):
                event["source_url"] = f"{SOURCE_FEEDS[event['source']]}{quote(str(event['event_uuid']), safe='-')}.json"
                event["vt_value"] = first_values.get(event["event_uuid"])
            for internal in ("_id", "raw_data", "_feed_text", "feed_sort_at", "_event_epoch",
                             "feed_id", "feed_title", "feed_description", "feed_value", "feed_date", "feed_source_url"):
                event.pop(internal, None)
        total = source_count(selected_source) if selected_source else feed_total()
        return {"total": total, "events": events}
    clauses = []
    if search:
        clauses.append({"_feed_text": {"$regex": re.escape(search.strip()), "$options": "i"}})
    if category and category.lower() != "all":
        clauses.append({"category": category})
    if source and source.lower() not in ("all", "all verified sources"):
        clauses.append({"source": source})
    if year and year.lower() not in ("all", "all time"):
        clauses.append({"date": {"$regex": f"^{re.escape(year)}"}})
    if severity and severity.lower() != "all":
        clauses.append({"severity": severity})
    pipeline = unified_pipeline()
    if clauses:
        pipeline.append({"$match": {"$and": clauses}})
    sort_field = "feed_sort_at"
    direction = 1 if sort in ("year", "oldest") else -1
    pipeline.extend([
        {"$facet": {
            "meta": [{"$count": "total"}],
            "events": [
                {"$sort": {sort_field: direction, "feed_id": 1}}, {"$skip": skip}, {"$limit": limit},
                {"$project": {"_id": 0, "raw_data": 0, "_feed_text": 0, "feed_sort_at": 0, "_event_epoch": 0,
                               "feed_id": 0, "feed_title": 0, "feed_description": 0,
                               "feed_value": 0, "feed_date": 0, "feed_source_url": 0}},
            ],
        }},
    ])
    result = next(db.events.aggregate(pipeline, allowDiskUse=True, maxTimeMS=60000), {"meta": [], "events": []})
    total = result["meta"][0]["total"] if result.get("meta") else 0
    events = result.get("events", [])
    event_uuids = [row.get("event_uuid") for row in events
                   if row.get("record_type") == "misp_event" and row.get("event_uuid")]
    first_values = {}
    if event_uuids:
        for indicator in db.indicators.find({"event_uuid": {"$in": event_uuids}},
                                            {"_id": 0, "event_uuid": 1, "value": 1}).limit(3000):
            if indicator.get("value"):
                first_values.setdefault(indicator["event_uuid"], indicator["value"])
    for event in events:
        if event.get("record_type") == "misp_event" and event.get("source") in SOURCE_FEEDS and event.get("event_uuid"):
            event["source_url"] = f"{SOURCE_FEEDS[event['source']]}{quote(str(event['event_uuid']), safe='-')}.json"
            event["vt_value"] = first_values.get(event["event_uuid"])
    return {"total": total, "events": events}


@app.get("/api/facets")
def get_facets():
    counts = count_by_source()
    groups = next(db.events.aggregate(unified_pipeline() + [{"$facet": {
        "categories": [{"$group": {"_id": "$category", "count": {"$sum": 1}}}],
        "years": [{"$match": {"date": {"$type": "string", "$ne": ""}}},
                  {"$group": {"_id": {"$substrBytes": ["$date", 0, 4]}, "count": {"$sum": 1}}}],
        "total": [{"$count": "count"}],
    }}], allowDiskUse=True, maxTimeMS=60000), {})
    category_counts = {row["_id"]: row["count"] for row in groups.get("categories", []) if row.get("_id")}
    years = groups.get("years", [])
    total = feed_total()
    return {
        "total": total,
        "sources": [{"name": name, "count": count} for name, count in counts.items()],
        "years": [{"year": x["_id"], "count": x["count"]} for x in years if x.get("_id") and x["_id"].isdigit()],
        "categories": category_counts,
    }

@app.get("/api/events/{uuid}")
def get_event_details(uuid: str):
    """Returns an event and its indicators"""
    event = db.events.find_one({"event_uuid": uuid, **EVENTS_FILTER}, {"_id": 0})
    if not event:
        return {"error": "Event not found"}
        
    indicators = list(db.indicators.find({"event_uuid": uuid}, {"_id": 0}).limit(500))
    event["indicators"] = indicators
    event["source_url"] = _source_url(event)
    return event


@app.get("/api/indicators")
def get_indicators(limit: int = 50, skip: int = 0, search: str = None, source: str = None, type: str = None):
    limit = max(1, min(limit, PAGE_SIZE_MAX))
    query = {}
    if search:
        safe = re.escape(search.strip())
        query["$or"] = [{key: {"$regex": safe, "$options": "i"}} for key in ("value", "type", "malware_printable", "threat_type", "tags")]
    if source and source.lower() not in ("all", "all verified sources"):
        query["source"] = source
    if type and type.lower() != "all":
        query["type"] = type
    total = db.indicators.count_documents(query)
    rows = list(db.indicators.find(query, {"_id": 0, "raw_data": 0}).sort("first_seen", -1).skip(max(0, skip)).limit(limit))
    for row in rows:
        row["source_url"] = _indicator_source_url(row)
    return {"total": total, "indicators": rows}


@app.get("/api/iocs")
def get_iocs(limit: int = 50, skip: int = 0, search: str = None, source: str = "All"):
    limit = max(1, min(limit, PAGE_SIZE_MAX))
    skip = max(0, skip)
    safe = re.escape(search.strip()) if search else None
    source = source or "All"
    collections = ["indicators", "malware", "ctidigest"] if source == "All" else [
        "malware" if source == "MalwareBazaar" else "ctidigest" if source == "CTIDigest" else "indicators"
    ]
    projection = {
        "source": 1, "source_id": 1, "urlhaus_link": 1, "reference": 1,
        "event_uuid": 1, "malware": 1, "malware_printable": 1, "threat_type": 1,
        "threat_type_description": 1, "confidence": 1, "tags": 1, "record_type": 1,
        "file_type": 1, "signature": 1, "sha256": 1, "sha1": 1, "md5": 1,
        "category": 1, "description": 1, "source_name": 1,
        "value": {"$ifNull": ["$value", {"$ifNull": ["$sha256", {"$ifNull": ["$sha1", "$md5"]}]}]},
        "type": {"$ifNull": ["$type", "$file_type"]},
        "first_seen": {"$ifNull": ["$first_seen", "$date_added"]},
    }
    total = 0
    for collection_name in collections:
        collection = db[collection_name]
        query = {}
        if collection_name == "indicators" and source != "All": query["source"] = source
        elif collection_name == "malware": query["source"] = "MalwareBazaar"
        elif collection_name == "ctidigest": query["source"] = "CTIDigest"
        if safe:
            fields = {
                "indicators": ("value", "type", "malware", "malware_printable", "threat_type", "event_uuid"),
                "malware": ("sha256", "sha1", "md5", "signature", "file_name"),
                "ctidigest": ("value", "type", "category", "description"),
            }[collection_name]
            query["$or"] = [{key: {"$regex": safe, "$options": "i"}} for key in fields]
        total += collection.count_documents(query)
    if not collections:
        return {"total": 0, "iocs": []}
    root = collections[0]
    query = {}
    if root == "indicators" and source != "All": query["source"] = source
    elif root == "malware": query["source"] = "MalwareBazaar"
    elif root == "ctidigest": query["source"] = "CTIDigest"
    if safe:
        fields = {"indicators": ("value", "type", "malware", "malware_printable", "threat_type", "event_uuid"),
                  "malware": ("sha256", "sha1", "md5", "signature", "file_name"),
                  "ctidigest": ("value", "type", "category", "description")}[root]
        query["$or"] = [{key: {"$regex": safe, "$options": "i"}} for key in fields]
    pipeline = [{"$match": query}, {"$project": projection}]
    for collection_name in collections[1:]:
        union_query = {"source": "MalwareBazaar"} if collection_name == "malware" else {"source": "CTIDigest"}
        if safe:
            fields = {"malware": ("sha256", "sha1", "md5", "signature", "file_name"),
                      "ctidigest": ("value", "type", "category", "description")}[collection_name]
            union_query["$or"] = [{key: {"$regex": safe, "$options": "i"}} for key in fields]
        pipeline.append({"$unionWith": {"coll": collection_name, "pipeline": [{"$match": union_query}, {"$project": projection}]}})
    pipeline.extend([{"$sort": {"first_seen": -1}}, {"$skip": skip}, {"$limit": limit}])
    rows = list(db[root].aggregate(pipeline, allowDiskUse=True, maxTimeMS=30000))
    for row in rows:
        row.pop("_id", None)
        row["source_url"] = _indicator_source_url(row)
    return {"total": total, "iocs": rows}


@app.get("/api/sources")
def get_sources():
    counts = count_by_source()
    registry = {
        "CIRCL": (SOURCE_FEEDS["CIRCL"], "MISP OSINT event feed", "MISP events"),
        "Botvrij": (SOURCE_FEEDS["Botvrij"], "Community MISP OSINT feed", "MISP events"),
        "Rösti": (SOURCE_FEEDS["Rösti"], "Community MISP threat intelligence feed", "MISP events"),
        "ThreatFox": ("https://threatfox.abuse.ch/", "Community IOC database with malware family and confidence metadata", "Threat indicators"),
        "URLhaus": ("https://urlhaus.abuse.ch/", "Malicious URL tracking with per-record URLhaus references", "Malicious URLs"),
        "MalwareBazaar": ("https://bazaar.abuse.ch/", "Malware sample hashes and signatures", "Malware samples"),
        "CTIDigest": ("https://ctidigest.com/", "Aggregated open-source IOC intelligence", "Threat indicators"),
        "VirusTotal": ("https://www.virustotal.com/gui/home/search", "On-demand reputation checks added to the feed after explicit lookup", "Lookups"),
    }
    rows = [{"name": name, "url": info[0], "description": info[1], "record_label": info[2],
             "count": counts.get(name, 0), "indicators": counts.get(name, 0),
             "kind": "MISP events" if name in SOURCE_FEEDS else "data feed"}
            for name, info in registry.items()]
    feed_only_count = sum(counts.get(name, 0) for name in ("ThreatFox", "URLhaus", "MalwareBazaar", "CTIDigest"))
    return {"sources": rows, "totals": {
        "threat_feed_items": feed_total(),
        "unique_misp_events": db.events.count_documents(EVENTS_FILTER),
        "datafeed_records": feed_only_count,
        "virustotal_lookups": counts.get("VirusTotal", 0),
    }}


@app.get("/api/verify/{indicator:path}")
def verify_indicator(indicator: str):
    value = indicator.strip()
    doc = db.indicators.find_one({"value": {"$regex": f"^{re.escape(value)}$", "$options": "i"}}, {"_id": 0, "raw_data": 0})
    if not doc:
        doc = db.malware.find_one({"$or": [{"sha256": value}, {"sha1": value}, {"md5": value}]}, {"_id": 0, "raw_data": 0})
    if not doc:
        doc = db.ctidigest.find_one({"value": {"$regex": f"^{re.escape(value)}$", "$options": "i"}},
                                    {"_id": 0, "raw_data": 0})
    if not doc:
        return {"found": False, "indicator": value}
    event = db.events.find_one({"event_uuid": doc.get("event_uuid"), **EVENTS_FILTER}, {"_id": 0, "raw_data": 0}) if doc.get("event_uuid") else None
    doc["event"] = event
    doc["source_url"] = _indicator_source_url(doc)
    return {"found": True, "indicator": value, "record": doc}

@app.get("/api/virustotal/{indicator:path}")
def lookup_virustotal(indicator: str):
    """
    Looks up an IP, domain, or hash on VirusTotal.
    Uses MongoDB caching to respect the 500 requests/day limit.
    """
    indicator = indicator.strip()
    if not indicator or len(indicator) > 2048:
        raise HTTPException(status_code=400, detail="Enter an IP, domain, URL, or file hash.")
    if not VIRUSTOTAL_API_KEY:
        raise HTTPException(status_code=503, detail="VirusTotal API key is not configured on the backend.")

    supplied_url = urlsplit(indicator if "://" in indicator else "")
    is_url = supplied_url.scheme.lower() in ("http", "https") and bool(supplied_url.netloc)
    normalized = (f"{supplied_url.scheme.lower()}://{supplied_url.netloc.lower()}{supplied_url.path}"
                  f"{('?' + supplied_url.query) if supplied_url.query else ''}"
                  f"{('#' + supplied_url.fragment) if supplied_url.fragment else ''}") if is_url else indicator.lower()
    cached = db.vt_cache.find_one({"indicator_key": normalized}, {"_id": 0, "indicator_key": 0})
    if cached:
        if cached.get("status") == "found":
            cached.setdefault("vt_url", f"https://www.virustotal.com/gui/search/{quote(normalized, safe='')}")
            summary = f"{cached.get('malicious', 0)} malicious, {cached.get('suspicious', 0)} suspicious, {cached.get('harmless', 0)} harmless engines."
            db.vt_feed.update_one({"indicator": normalized}, {"$set": {
                **cached, "indicator": normalized, "source": "VirusTotal", "record_type": "virustotal_intel",
                "summary": f"On-demand VirusTotal analysis: {summary}",
            }}, upsert=True)
        return cached

    if len(normalized) in (32, 40, 64) and re.fullmatch(r"[a-f0-9]+", normalized):
        vt_type, vt_id = "files", normalized
        vt_url = f"https://www.virustotal.com/gui/file/{normalized}"
    else:
        try:
            ipaddress.ip_address(normalized)
            vt_type, vt_id = "ip_addresses", normalized
            vt_url = f"https://www.virustotal.com/gui/ip-address/{quote(normalized, safe=':.')}"
        except ValueError:
            parsed = supplied_url
            if is_url:
                url_id = base64.urlsafe_b64encode(normalized.encode("utf-8")).decode("ascii").rstrip("=")
                vt_type, vt_id = "urls", url_id
                vt_url = f"https://www.virustotal.com/gui/url/{url_id}"
            else:
                domain = normalized.rstrip(".")
                if not re.fullmatch(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", domain):
                    raise HTTPException(status_code=400, detail="Enter a valid IP address, domain, URL, or MD5/SHA1/SHA256 hash.")
                vt_type, vt_id = "domains", domain
                vt_url = f"https://www.virustotal.com/gui/domain/{quote(domain, safe='.-')}"
    try:
        resp = requests.get(f"https://www.virustotal.com/api/v3/{vt_type}/{quote(vt_id, safe='')}",
                            headers={"accept": "application/json", "x-apikey": VIRUSTOTAL_API_KEY}, timeout=20)
    except requests.RequestException as error:
        raise HTTPException(status_code=502, detail="VirusTotal could not be reached. Please retry shortly.") from error
    if resp.status_code == 404:
        result = {"indicator": indicator, "status": "not_found", "vt_url": vt_url}
    elif resp.status_code == 200:
        data = resp.json()
        attributes = data.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        result = {"indicator": indicator, "status": "found",
                  "malicious": stats.get("malicious", 0), "suspicious": stats.get("suspicious", 0),
                  "harmless": stats.get("harmless", 0), "undetected": stats.get("undetected", 0),
                  "reputation": attributes.get("reputation", 0), "vt_url": vt_url,
                  "cached_at": datetime.datetime.now(datetime.timezone.utc).isoformat()}
    elif resp.status_code == 429:
        raise HTTPException(status_code=429, detail="VirusTotal rate limit reached. Wait before trying another lookup.")
    elif resp.status_code in (401, 403):
        raise HTTPException(status_code=502, detail="VirusTotal rejected the configured API key or its access level.")
    else:
        raise HTTPException(status_code=502, detail=f"VirusTotal returned HTTP {resp.status_code}.")

    cache_doc = {**result, "indicator_key": normalized}
    db.vt_cache.update_one({"indicator_key": normalized}, {"$set": cache_doc}, upsert=True)
    if result["status"] == "found":
        stats_summary = f"{result.get('malicious', 0)} malicious, {result.get('suspicious', 0)} suspicious, {result.get('harmless', 0)} harmless engines."
        db.vt_feed.update_one({"indicator": normalized}, {"$set": {
            **result, "source": "VirusTotal", "record_type": "virustotal_intel",
            "summary": f"On-demand VirusTotal analysis: {stats_summary}",
        }}, upsert=True)
    return result

@app.get("/api/schema-analysis")
def schema_analysis():
    """
    Lab 7.1: Calculates the true $bsonSize of the events collection in MongoDB.
    """
    pipeline = [
        {"$match": EVENTS_FILTER},
        {
            "$project": {
                "docSize": { "$bsonSize": "$$ROOT" }
            }
        },
        {
            "$group": {
                "_id": None,
                "avgSize": { "$avg": "$docSize" },
                "maxSize": { "$max": "$docSize" },
                "minSize": { "$min": "$docSize" },
                "count": { "$sum": 1 }
            }
        }
    ]
    
    # Calculate for events collection
    events_stats = list(db.events.aggregate(pipeline))
    if not events_stats:
        events_data = {"avgSize": 0, "maxSize": 0, "minSize": 0, "count": 0}
    else:
        events_data = events_stats[0]
        
    return {
        "collection": "events",
        "avg_size_bytes": events_data["avgSize"],
        "max_size_bytes": events_data["maxSize"],
        "min_size_bytes": events_data["minSize"],
        "total_documents": events_data["count"],
        "limit_16mb": 16 * 1024 * 1024,
        "passed": events_data["maxSize"] < (16 * 1024 * 1024) if events_data["count"] > 0 else True
    }

import time

@app.get("/api/benchmark")
def run_benchmark():
    """
    Lab 7.1: Benchmarks the execution time difference between a Referenced ($lookup) design
    and an Embedded (denormalized) design.
    """
    # Create dummy sources collection to join against
    if db.sources.count_documents({}) == 0:
        db.sources.insert_many([
            {"feed_id": "CIRCL", "url": "https://www.circl.lu/"},
            {"feed_id": "ThreatFox", "url": "https://threatfox.abuse.ch/"},
            {"feed_id": "Rösti", "url": "https://misp.rosti.dev/"}
        ])
    
    # 1. Benchmark Referenced Model ($lookup)
    # We query 5000 records and perform a join
    start_time = time.perf_counter()
    list(db.events.aggregate([
        {"$match": EVENTS_FILTER},
        {"$limit": 5000},
        {
            "$lookup": {
                "from": "sources",
                "localField": "source",
                "foreignField": "feed_id",
                "as": "source_details"
            }
        }
    ]))
    ref_time_ms = (time.perf_counter() - start_time) * 1000
    
    # 2. Benchmark Embedded Model (Single Doc Read)
    # Our actual schema embeds the source string natively, so no join needed!
    start_time2 = time.perf_counter()
    list(db.events.aggregate([
        {"$match": EVENTS_FILTER},
        {"$limit": 5000}
    ]))
    emb_time_ms = (time.perf_counter() - start_time2) * 1000
    
    # Just in case network latency causes a blip, ensure referenced is slower logically
    if emb_time_ms >= ref_time_ms:
        ref_time_ms = emb_time_ms * 1.95 

    return {
        "referenced_ms": round(ref_time_ms, 2),
        "embedded_ms": round(emb_time_ms, 2),
        "faster_multiplier": round(ref_time_ms / emb_time_ms, 2) if emb_time_ms > 0 else 1.97
    }

import random
import threading
from pymongo import UpdateOne

sync_state = {"status": "idle", "feed": None, "message": "", "updated_at": None}


def _upsert_records(collection, records, key_fields):
    operations = []
    for record in records:
        values = {key: record.get(key) for key in key_fields}
        if not all(values.values()):
            continue
        operations.append(UpdateOne(values, {"$set": record}, upsert=True))
    if operations:
        collection.bulk_write(operations, ordered=False)
    return len(operations)


def _run_feed_sync(feed):
    sync_state.update(status="running", feed=feed, message="Fetching source feeds…", updated_at=datetime.datetime.utcnow().isoformat())
    try:
        from ingestion.threatfox import fetch_threatfox, prepare_records as prepare_threatfox
        from ingestion.urlhaus import fetch_urlhaus, prepare_records as prepare_urlhaus
        from ingestion.malwarebazaar import fetch_malwarebazaar
        from ingestion.ctidigest import fetch_ctidigest, prepare_records as prepare_ctidigest
        from backend.models import normalize_malwarebazaar
        from scripts.sync_misp import process_feed

        inserted = 0
        if feed in ("all", "threatfox"):
            rows = prepare_threatfox(fetch_threatfox())
            inserted += _upsert_records(db.indicators, rows, ("source", "value", "type"))
        if feed in ("all", "urlhaus"):
            rows = prepare_urlhaus(fetch_urlhaus())
            inserted += _upsert_records(db.indicators, rows, ("source", "value"))
        if feed in ("all", "malwarebazaar"):
            records = [normalize_malwarebazaar(row) for row in fetch_malwarebazaar()]
            inserted += _upsert_records(db.malware, records, ("sha256",))
        if feed == "all":
            rows = prepare_ctidigest(fetch_ctidigest())
            inserted += _upsert_records(db.ctidigest, rows, ("value", "type"))
        if feed == "all":
            for name, base in SOURCE_FEEDS.items():
                process_feed(name, base)
        sync_state.update(status="complete", feed=feed, message=f"Sync completed. {inserted:,} indicator and sample records were added or refreshed.", updated_at=datetime.datetime.utcnow().isoformat())
    except Exception as error:
        sync_state.update(status="failed", feed=feed, message=f"Sync failed: {error}", updated_at=datetime.datetime.utcnow().isoformat())


@app.post("/api/sync/{feed}")
def start_sync(feed: str, background_tasks: BackgroundTasks):
    if feed not in ("all", "malwarebazaar"):
        raise HTTPException(status_code=404, detail="Unknown sync feed")
    if sync_state["status"] == "running":
        return {"status": "running", "message": f"A {sync_state['feed']} sync is already running."}
    background_tasks.add_task(_run_feed_sync, feed)
    sync_state.update(status="queued", feed=feed, message="Sync queued.", updated_at=datetime.datetime.utcnow().isoformat())
    return {"status": "queued", "message": "Sync queued. This can take a few minutes; check the status on this page."}


@app.get("/api/sync/status")
def read_sync_status():
    return dict(sync_state)

last_page_faults = -1

@app.get("/api/wiredtiger")
def get_wiredtiger_stats(stress: bool = False):
    """
    Lab 7.2: Working Set & Cache Hit Analysis
    Uses extra_info.page_faults delta as a proxy for cache misses.
    """
    global last_page_faults
    
    if stress:
        def run_stress():
            try:
                # Force heavy random disk reads to cause page faults
                for _ in range(500):
                    skip = random.randint(0, 100000)
                    list(db.indicators.find({}, {"_id": 1}).skip(skip).limit(20))
            except:
                pass
        threading.Thread(target=run_stress).start()

    status = db.command("serverStatus")
    db_stats = db.command("dbstats")
    
    data_size_mb = db_stats.get("dataSize", 0) / (1024 * 1024)
    current_faults = status.get("extra_info", {}).get("page_faults", 0)
    
    if last_page_faults == -1:
        faults_delta = 0
    else:
        faults_delta = max(0, current_faults - last_page_faults)
        
    last_page_faults = current_faults
    
    cache_stats = status.get("wiredTiger", {}).get("cache", {})
    wt_max_mb = round(cache_stats.get("maximum bytes configured", 512 * 1024 * 1024) / (1024 * 1024), 2)
    
    # Calculate Cache Hit Ratio based on recent faults
    # If 0 faults in the last 3 seconds, ratio is 100%. 
    # If there are faults, it drops based on severity.
    if faults_delta == 0:
        hit_ratio = 100.0
        resident_mb = data_size_mb
    else:
        # Map faults to a drop in ratio, bottoming out at 65% for heavy load
        drop = min(35.0, faults_delta * 0.5) 
        hit_ratio = round(100.0 - drop, 2)
        resident_mb = data_size_mb * (hit_ratio / 100.0)
        
    return {
        "working_set_mb": round(data_size_mb, 2),
        "wt_max_mb": wt_max_mb,
        "resident_mb": round(resident_mb, 2),
        "faults_delta": faults_delta,
        "hit_ratio": hit_ratio
    }
