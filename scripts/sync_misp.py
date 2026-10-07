import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from backend.db import events_collection, indicators_collection
from backend.models import normalize_misp_event, normalize_misp_indicator
from backend.misp_galaxy import enricher

FEEDS = {
    "CIRCL": "https://www.circl.lu/doc/misp/feed-osint/",
    "Botvrij": "https://www.botvrij.eu/data/feed-osint/",
    "Rösti": "https://misp.rosti.dev/"
}

def fetch_manifest(base_url):
    print(f"Fetching manifest from {base_url}...")
    try:
        resp = requests.get(base_url + "manifest.json", timeout=60)
        resp.raise_for_status()
        data = resp.json()
        if isinstance(data, dict):
            return list(data.keys())
        if isinstance(data, list):
            return data
    except Exception:
        # Fallback for Rösti or feeds without manifest.json
        print(f"No manifest.json found at {base_url}. Attempting to parse directory...")
        try:
            resp = requests.get(base_url, timeout=60)
            import re
            files = re.findall(r'href="([^"]+\.json)"', resp.text)
            return [f.replace('.json', '') for f in files if f != 'manifest.json']
        except Exception as e:
            print(f"Failed to fetch manifest for {base_url}: {e}")
            return []

def fetch_event(base_url, uuid):
    try:
        resp = requests.get(f"{base_url}{uuid}.json", timeout=30)
        resp.raise_for_status()
        return resp.json().get("Event")
    except Exception:
        return None

def process_feed(source_name, base_url, limit=None):
    print(f"\n{'='*60}\nIngesting {source_name} MISP Feed\n{'='*60}")
    
    uuids = fetch_manifest(base_url)
    print(f"Found {len(uuids)} events in {source_name} manifest.")
    
    # Event UUID is the canonical identity across all MISP feeds.
    existing_uuids = set(events_collection.distinct("event_uuid", {"record_type": "misp_event"}))
    source_existing = existing_uuids.intersection(uuids)
    if source_existing:
        events_collection.update_many(
            {"event_uuid": {"$in": list(source_existing)}, "record_type": "misp_event"},
            {"$addToSet": {"sources": source_name}},
        )
    new_uuids = [u for u in uuids if u not in existing_uuids]
    
    print(f"Skipping {len(existing_uuids)} already ingested events.")
    print(f"Need to fetch {len(new_uuids)} new events.")
    
    if limit:
        new_uuids = new_uuids[:limit]
        print(f"Limiting fetch to {limit} events for testing.")

    if not new_uuids:
        print(f"No new events for {source_name}; source provenance was refreshed.")
        return

    enricher.initialize()

    def fetch_and_process(uuid):
        event = fetch_event(base_url, uuid)
        if not event:
            return None, []
            
        normalized_event = normalize_misp_event(event, source_name)
        normalized_event["event_uuid"] = uuid
        
        # --- GALAXY ENRICHMENT LAYER ---
        clusters = enricher.enrich(event)
        normalized_event["galaxy_clusters"] = clusters
        
        indicators = []
        
        # Extract attributes
        all_attributes = list(event.get("Attribute", []))
        for obj in event.get("Object", []):
            if isinstance(obj, dict):
                all_attributes.extend(obj.get("Attribute", []))
                
        for attr in all_attributes:
            ind = normalize_misp_indicator(attr, uuid, source_name)
            if ind.get("value"):
                # Inherit galaxy clusters to indicators for easier querying
                ind["galaxy_clusters"] = clusters
                indicators.append(ind)
                
        return normalized_event, indicators

    events_to_insert = []
    indicators_to_insert = []
    
    completed = 0
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(fetch_and_process, uuid): uuid for uuid in new_uuids}
        
        for future in as_completed(futures):
            ev, inds = future.result()
            if ev:
                events_to_insert.append(ev)
                indicators_to_insert.extend(inds)
            
            completed += 1
            if completed % 100 == 0 or completed == len(new_uuids):
                print(f"Processed {completed}/{len(new_uuids)} events for {source_name}...")

    # Insert in batches
    if events_to_insert:
        print(f"Inserting {len(events_to_insert)} events...")
        events_collection.insert_many(events_to_insert, ordered=False)
        
    if indicators_to_insert:
        # Batch insert indicators since there can be many
        print(f"Inserting {len(indicators_to_insert)} indicators...")
        batch_size = 5000
        for i in range(0, len(indicators_to_insert), batch_size):
            indicators_collection.insert_many(indicators_to_insert[i:i+batch_size], ordered=False)

def main():
    import argparse
    parser = argparse.ArgumentParser(description="MISP Feed Sync")
    parser.add_argument("--limit", type=int, default=None, help="Limit number of events per feed")
    args = parser.parse_args()

    for name, url in FEEDS.items():
        process_feed(name, url, limit=args.limit)
        
    print("\nCreating MISP indexes if they don't exist...")
    events_collection.create_index("event_uuid", unique=True)
    events_collection.create_index("source")
    events_collection.create_index("galaxy_clusters")
    
    indicators_collection.create_index("event_uuid")
    indicators_collection.create_index("source")
    indicators_collection.create_index("value")
    indicators_collection.create_index("galaxy_clusters")
    print("Done!")

if __name__ == "__main__":
    main()
