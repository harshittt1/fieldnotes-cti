import requests
import re
from typing import List, Dict, Set

GALAXY_NAMES = ["threat-actor", "malpedia", "tool"]
GALAXY_BASE_URL = "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/{name}.json"

BLOCKLIST = {
    "action", "group", "admin", "system", "network", "server", "client", 
    "user", "data", "test", "demo", "unknown", "do not", "explorer", "update",
    "shell", "command", "process", "service", "file", "web", "windows", "linux", "mac",
    "security", "threat", "actor", "tool", "malware", "virus", "trojan", "worm", "bot",
    "botnet", "campaign", "operation", "project", "team", "author", "hacker", "attacker"
}

class GalaxyEnricher:
    def __init__(self):
        self.clusters: List[Dict] = []
        self.known_names: Set[str] = set()
        self.alias_map: Dict[str, str] = {}  # alias.lower() -> primary_name
        self.initialized = False

    def initialize(self):
        if self.initialized:
            return
        
        print("Initializing MISP Galaxy enrichment...")
        for name in GALAXY_NAMES:
            url = GALAXY_BASE_URL.format(name=name)
            try:
                resp = requests.get(url, timeout=30)
                resp.raise_for_status()
                data = resp.json()
                for cluster in data.get("values", []):
                    primary_name = cluster.get("value")
                    if not primary_name:
                        continue
                    
                    # Store primary
                    self.clusters.append(cluster)
                    self.known_names.add(primary_name)
                    if primary_name.lower() not in BLOCKLIST and len(primary_name) > 3:
                        self.alias_map[primary_name.lower()] = primary_name

                    # Store aliases
                    meta = cluster.get("meta", {})
                    synonyms = meta.get("synonyms", [])
                    if isinstance(synonyms, list):
                        for syn in synonyms:
                            if syn.lower() not in BLOCKLIST and len(syn) > 3:
                                self.alias_map[syn.lower()] = primary_name
                                
            except Exception as e:
                print(f"Failed to fetch galaxy {name}: {e}")
        
        self.initialized = True
        print(f"Galaxy initialized with {len(self.known_names)} primary entities and {len(self.alias_map)} total aliases.")

    def enrich(self, event_data: Dict) -> List[str]:
        if not self.initialized:
            self.initialize()
            
        found_clusters = set()
        
        # Priority 1: Native MISP Galaxy relationships/tags
        tags = event_data.get("Tag", [])
        for tag_obj in tags:
            tag_name = tag_obj.get("name", "")
            # e.g. misp-galaxy:threat-actor="APT29"
            if "misp-galaxy" in tag_name.lower():
                # Extract the value in quotes if present
                match = re.search(r'="(.*?)"', tag_name)
                if match:
                    val = match.group(1)
                    found_clusters.add(val)
                else:
                    # sometimes it's like misp-galaxy:threat-actor=APT29
                    parts = tag_name.split("=")
                    if len(parts) > 1:
                        found_clusters.add(parts[1].strip('"'))
                        
        # Priority 2: Galaxy alias matching second
        info_text = event_data.get("info", "")
        if info_text:
            words = re.findall(r'\b[A-Za-z0-9-]+\b', info_text)
            for i in range(len(words)):
                # 1 word
                w1 = words[i].lower()
                if w1 in self.alias_map:
                    found_clusters.add(self.alias_map[w1])
                
                # 2 words
                if i < len(words) - 1:
                    w2 = f"{words[i]} {words[i+1]}".lower()
                    if w2 in self.alias_map:
                        found_clusters.add(self.alias_map[w2])
                        
                # 3 words
                if i < len(words) - 2:
                    w3 = f"{words[i]} {words[i+1]} {words[i+2]}".lower()
                    if w3 in self.alias_map:
                        found_clusters.add(self.alias_map[w3])

        return list(found_clusters)

enricher = GalaxyEnricher()
