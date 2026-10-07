"""Read-only unified feed view over the existing source collections."""
from backend.db import db

EVENTS_FILTER = {"record_type": "misp_event"}
FEED_COLLECTIONS = ("events", "indicators", "malware", "ctidigest", "vt_feed")


def source_pipeline(name):
    if name == "events":
        return [{"$match": EVENTS_FILTER}, {"$set": {
            "feed_id": {"$toString": {"$ifNull": ["$event_uuid", "$_id"]}},
            "feed_title": {"$ifNull": ["$info", "MISP threat report"]},
            "feed_description": {"$ifNull": ["$info", "MISP threat report"]},
            "feed_value": "", "feed_date": {"$ifNull": ["$date", ""]},
            "feed_source_url": "", "indicator_count": {"$ifNull": ["$indicator_count", 0]},
        }}]
    if name == "indicators":
        return [{"$match": {"source": {"$in": ["ThreatFox", "URLhaus"]}}}, {"$set": {
            "feed_id": {"$concat": ["$source", ":", {"$toString": {"$ifNull": ["$source_id", "$value"]}}]},
            "feed_title": {"$switch": {"branches": [
                {"case": {"$eq": ["$source", "ThreatFox"]}, "then": {"$concat": ["ThreatFox IOC: ", {"$ifNull": ["$malware_printable", {"$ifNull": ["$type", "indicator"]}]}]}},
                {"case": {"$eq": ["$source", "URLhaus"]}, "then": {"$concat": ["URLhaus malicious URL: ", {"$ifNull": ["$value", "Unknown URL"]}]}}
            ], "default": "Threat indicator"}},
            "feed_description": {"$ifNull": ["$threat_type_description", {"$ifNull": ["$description", {"$ifNull": ["$type_description", "Threat indicator from source feed"]}]}]},
            "feed_value": {"$ifNull": ["$value", ""]},
            "feed_date": {"$ifNull": ["$first_seen", {"$ifNull": ["$date_added", ""]}]},
            "feed_source_url": {"$switch": {"branches": [
                {"case": {"$eq": ["$source", "ThreatFox"]}, "then": {"$cond": [{"$ifNull": ["$source_id", False]}, {"$concat": ["https://threatfox.abuse.ch/ioc/", {"$toString": "$source_id"}, "/"]}, "https://threatfox.abuse.ch/"]}},
                {"case": {"$eq": ["$source", "URLhaus"]}, "then": {"$ifNull": ["$urlhaus_link", "https://urlhaus.abuse.ch/"]}}
            ], "default": ""}},
            "indicator_count": 1,
        }}]
    if name == "malware":
        return [{"$match": {"source": "MalwareBazaar"}}, {"$set": {
            "feed_id": {"$concat": ["MalwareBazaar:", {"$toString": {"$ifNull": ["$sha256", "$_id"]}}]},
            "feed_title": {"$concat": ["MalwareBazaar sample: ", {"$ifNull": ["$signature", {"$ifNull": ["$file_name", "malware sample"]}]}]},
            "feed_description": {"$concat": ["Verified malware sample", {"$cond": [{"$ifNull": ["$file_name", False]}, {"$concat": [" — ", "$file_name"]}, ""]}]},
            "feed_value": {"$ifNull": ["$sha256", ""]}, "feed_date": {"$ifNull": ["$first_seen", ""]},
            "feed_source_url": {"$cond": [{"$ifNull": ["$sha256", False]}, {"$concat": ["https://bazaar.abuse.ch/sample/", {"$toString": "$sha256"}, "/"]}, "https://bazaar.abuse.ch/"]},
            "indicator_count": 1,
        }}]
    if name == "ctidigest":
        return [{"$match": {"source": "CTIDigest"}}, {"$set": {
            "feed_id": {"$concat": ["CTIDigest:", {"$toString": {"$ifNull": ["$value", "$_id"]}}]},
            "feed_title": {"$concat": ["CTIDigest ", {"$ifNull": ["$type", "indicator"]}, ": ", {"$ifNull": ["$value", ""]}]},
            "feed_description": {"$ifNull": ["$description", {"$concat": ["Aggregated from ", {"$ifNull": ["$source_name", "CTIDigest"]}, " intelligence feed"]}]},
            "feed_value": {"$ifNull": ["$value", ""]}, "feed_date": {"$ifNull": ["$first_seen", ""]},
            "feed_source_url": {"$switch": {"branches": [
                {"case": {"$eq": ["$source_name", "AbuseIPDB"]}, "then": {"$cond": [{"$ifNull": ["$value", False]}, {"$concat": ["https://www.abuseipdb.com/check/", {"$toString": "$value"}]}, "https://www.abuseipdb.com/"]}},
                {"case": {"$eq": ["$source_name", "CISA KEV"]}, "then": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"},
                {"case": {"$eq": ["$source_name", "Emerging Threats"]}, "then": "https://rules.emergingthreats.net/"},
                {"case": {"$eq": ["$source_name", "Feodo Tracker"]}, "then": "https://feodotracker.abuse.ch/"},
                {"case": {"$eq": ["$source_name", "IPsum"]}, "then": "https://github.com/stamparm/ipsum/blob/master/ipsum.txt"},
                {"case": {"$eq": ["$source_name", "Tor Exit Nodes"]}, "then": "https://check.torproject.org/torbulkexitlist"}
            ], "default": {"$ifNull": ["$reference", "https://ctidigest.com/"]}}},
            "indicator_count": 1,
        }}]
    if name == "vt_feed":
        return [{"$set": {
            "feed_id": {"$toString": {"$ifNull": ["$indicator", "$_id"]}},
            "feed_title": {"$concat": ["VirusTotal intelligence: ", {"$ifNull": ["$indicator", ""]}]},
            "feed_description": {"$ifNull": ["$summary", "On-demand VirusTotal lookup"]},
            "feed_value": {"$ifNull": ["$indicator", ""]}, "feed_date": {"$ifNull": ["$cached_at", ""]},
            "feed_source_url": {"$ifNull": ["$vt_url", "https://www.virustotal.com/gui/search/"]}, "indicator_count": 1,
        }}]
    return []


def normalization_pipeline():
    return [
        {"$set": {
            "source": {"$ifNull": ["$source", "MISP"]},
            "event_uuid": {"$ifNull": ["$event_uuid", "$feed_id"]},
            "info": {"$ifNull": ["$feed_title", "$info"]},
            "description": {"$ifNull": ["$feed_description", "$info"]},
            "value": {"$ifNull": ["$feed_value", ""]}, "date": {"$ifNull": ["$feed_date", ""]},
            "source_url": {"$ifNull": ["$feed_source_url", ""]},
            "record_type": {"$ifNull": ["$record_type", "misp_event"]},
            "indicator_count": {"$ifNull": ["$indicator_count", 0]},
        }},
        {"$set": {"_event_epoch": {"$convert": {"input": "$timestamp", "to": "long", "onError": None, "onNull": None}}}},
        {"$set": {"feed_sort_at": {"$cond": [
            {"$and": [{"$eq": ["$record_type", "misp_event"]}, {"$ne": ["$_event_epoch", None]}]},
            {"$toDate": {"$multiply": ["$_event_epoch", 1000]}},
            {"$dateFromString": {
                "dateString": {"$replaceOne": {"input": {"$ifNull": ["$date", ""]}, "find": " UTC", "replacement": "Z"}},
                "onError": {"$ifNull": ["$ingested_at", None]}, "onNull": {"$ifNull": ["$ingested_at", None]},
            }},
        ]}}},
        {"$set": {"_feed_text": {"$toLower": {"$concat": [
            {"$ifNull": ["$info", ""]}, " ", {"$ifNull": ["$description", ""]}, " ",
            {"$ifNull": ["$category", ""]}, " ", {"$ifNull": ["$value", ""]}, " ",
            {"$ifNull": ["$type", ""]}, " ", {"$ifNull": ["$threat_type", ""]}
        ]}}}},
        {"$set": {"category": {"$switch": {"branches": [
            {"case": {"$regexMatch": {"input": "$_feed_text", "regex": "ransom|locker|crypt(?:or|ing)"}}, "then": "Ransomware"},
            {"case": {"$regexMatch": {"input": "$_feed_text", "regex": "cve[- ]?\\d|vulnerabilit|zero.?day|exploit"}}, "then": "Vulnerabilities"},
            {"case": {"$regexMatch": {"input": "$_feed_text", "regex": "patch|security update|hotfix"}}, "then": "Patches"},
            {"case": {"$regexMatch": {"input": "$_feed_text", "regex": "government|gov|ministry|public sector"}}, "then": "Government"},
            {"case": {"$regexMatch": {"input": "$_feed_text", "regex": "android|ios|mobile|iphone|smartphone"}}, "then": "Mobile"},
            {"case": {"$regexMatch": {"input": "$_feed_text", "regex": "cloud|aws|azure|gcp|kubernetes"}}, "then": "Cloud"},
            {"case": {"$regexMatch": {"input": "$_feed_text", "regex": "iot|router|camera|mirai|embedded device"}}, "then": "IoT"},
            {"case": {"$regexMatch": {"input": "$_feed_text", "regex": "crypto|cryptograph|openssl|tls|certificate"}}, "then": "Cryptography"},
            {"case": {"$regexMatch": {"input": "$_feed_text", "regex": "compromis|breach|expos(?:ed|ure)|leak"}}, "then": "Compromised"},
            {"case": {"$regexMatch": {"input": "$_feed_text", "regex": "malware|trojan|stealer|botnet|payload|hash"}}, "then": "Malware"}
        ], "default": "Threat-Actors"}}}},
        {"$set": {"severity": {"$switch": {"branches": [
            {"case": {"$regexMatch": {"input": "$_feed_text", "regex": "critical"}}, "then": "Critical"},
            {"case": {"$eq": ["$record_type", "misp_event"]}, "then": {"$switch": {"branches": [
                {"case": {"$eq": ["$threat_level_id", "1"]}, "then": "High"},
                {"case": {"$eq": ["$threat_level_id", "2"]}, "then": "Medium"},
                {"case": {"$eq": ["$threat_level_id", "3"]}, "then": "Low"}
            ], "default": "High"}}},
            {"case": {"$gte": [{"$ifNull": ["$confidence", 0]}, 90]}, "then": "Critical"},
            {"case": {"$gte": [{"$ifNull": ["$confidence", 0]}, 75]}, "then": "High"},
            {"case": {"$gte": [{"$ifNull": ["$confidence", 0]}, 50]}, "then": "Medium"}
        ], "default": "Low"}}}},
    ]


def unified_pipeline():
    pipeline = source_pipeline("events")
    for name in FEED_COLLECTIONS[1:]:
        pipeline.append({"$unionWith": {"coll": name, "pipeline": source_pipeline(name)}})
    return pipeline + normalization_pipeline()


def single_source_pipeline(name):
    return source_pipeline(name) + normalization_pipeline()


def count_by_source():
    origins = {row["_id"]: row["count"] for row in db.events.aggregate([
        {"$match": EVENTS_FILTER},
        {"$project": {"origins": {"$ifNull": ["$sources", ["$source"]]}}},
        {"$unwind": "$origins"}, {"$group": {"_id": "$origins", "count": {"$sum": 1}}},
    ]) if row.get("_id")}
    origins.update({
        "ThreatFox": db.indicators.count_documents({"source": "ThreatFox"}),
        "URLhaus": db.indicators.count_documents({"source": "URLhaus"}),
        "MalwareBazaar": db.malware.count_documents({"source": "MalwareBazaar"}),
        "CTIDigest": db.ctidigest.count_documents({"source": "CTIDigest"}),
        "VirusTotal": db.vt_feed.count_documents({}),
    })
    return origins


def feed_total():
    return (db.events.count_documents(EVENTS_FILTER)
            + db.indicators.count_documents({"source": {"$in": ["ThreatFox", "URLhaus"]}})
            + db.malware.count_documents({"source": "MalwareBazaar"})
            + db.ctidigest.count_documents({"source": "CTIDigest"})
            + db.vt_feed.count_documents({}))


def source_count(name):
    if name in ("CIRCL", "Botvrij", "Rösti"):
        return db.events.count_documents({"$and": [EVENTS_FILTER, {"$or": [{"source": name}, {"sources": name}]}]})
    if name in ("ThreatFox", "URLhaus"):
        return db.indicators.count_documents({"source": name})
    if name == "MalwareBazaar":
        return db.malware.count_documents({"source": name})
    if name == "CTIDigest":
        return db.ctidigest.count_documents({"source": name})
    if name == "VirusTotal":
        return db.vt_feed.count_documents({})
    return 0
