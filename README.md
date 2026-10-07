# Fieldnotes — Cyber Threat Intelligence Platform

**Live demo:** https://fieldnotes-cti.vercel.app

Fieldnotes pulls threat intelligence from several open-source feeds, normalizes it into one MongoDB Atlas store, and lets you search, filter and verify it from a single web dashboard. It also includes two database labs that analyse document sizes (`$bsonSize`) and WiredTiger cache / working-set behaviour on the real dataset.

---

## Features

- **Unified threat feed.** MISP events from CIRCL, Botvrij and Rösti, plus CTIDigest reports, deduplicated and sorted into 11 categories (Threat Actors, Vulnerabilities, Ransomware, Malware, Cloud, IoT, and more).
- **IOC database.** Indicators of compromise (IPs, domains, URLs, hashes) from ThreatFox, URLhaus and MalwareBazaar, searchable by source and type.
- **Filters.** Full-text search plus filters for category, source, year and severity (High / Medium / Low), with pagination.
- **Threat Verifier.** Checks an indicator against the stored feeds.
- **VirusTotal scan.** Live lookup of any IP, domain, URL or file hash through the VirusTotal API.
- **Source attribution.** Every record links back to its original feed.
- **Lab 7.1, Schema Analysis.** Per-collection document-size statistics using `$bsonSize`.
- **Lab 7.2, WiredTiger & Working Set.** Cache size, cache hit ratio, working-set estimate and a query benchmark.

## Tech stack

| Layer | Tools |
|---|---|
| Backend | Python, FastAPI, Uvicorn |
| Database | MongoDB Atlas (PyMongo) |
| Frontend | HTML, CSS, vanilla JavaScript |
| Data sources | MISP OSINT feeds (CIRCL, Botvrij, Rösti), CTIDigest, ThreatFox, URLhaus, MalwareBazaar, VirusTotal |
| Hosting | Vercel (frontend) |

## Project structure

```
.
├── backend/            FastAPI app, DB connection, config, normalizers
│   ├── app.py          API routes
│   ├── config.py       Loads env vars
│   ├── db.py           MongoDB client and collections
│   ├── models.py       Normalizers for each source
│   ├── threat_feed.py  Aggregation pipelines for the unified feed
│   └── misp_galaxy.py  MISP Galaxy enrichment
├── ingestion/          Fetchers for ThreatFox, URLhaus, MalwareBazaar, CIRCL, CTIDigest
├── scripts/            MISP sync, deduplication and DB repair scripts
├── sources/            Per-source exploration and test scripts
├── frontend/           Dashboard pages (feed, IOCs, sources, verifier, VirusTotal, labs)
├── requirements.txt
└── .env.example
```

## API endpoints

| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/events` | Paginated threat feed (`search`, `category`, `source`, `year`, `severity`) |
| GET | `/api/events/{uuid}` | Full details of one event |
| GET | `/api/facets` | Category and source counts for the filters |
| GET | `/api/indicators`, `/api/iocs` | Paginated IOC search |
| GET | `/api/sources` | Feed list with record counts |
| GET | `/api/verify/{indicator}` | Look up an indicator in the stored feeds |
| GET | `/api/virustotal/{indicator}` | Live VirusTotal lookup |
| GET | `/api/reports` | Annual security reports |
| GET | `/api/metrics` | Database metrics for the top bar |
| GET | `/api/schema-analysis` | Lab 7.1: `$bsonSize` statistics |
| GET | `/api/wiredtiger`, `/api/benchmark` | Lab 7.2: cache stats and query benchmark |
| POST | `/api/sync/{feed}` | Start a background sync for one feed |
| GET | `/api/sync/status` | Sync progress |

Interactive docs are served at `http://127.0.0.1:8000/docs` while the backend is running.

## Getting started

### 1. Clone and install

```bash
git clone https://github.com/<your-username>/fieldnotes-cti.git
cd fieldnotes-cti
python -m venv .venv
# Windows
.venv\Scripts\activate
# macOS / Linux
source .venv/bin/activate
pip install -r requirements.txt
```

### 2. Configure environment variables

Copy `.env.example` to `.env` and fill in your values:

```env
MONGODB_URI=mongodb+srv://<user>:<password>@<cluster>.mongodb.net/
THREATFOX_API_KEY=...
URLHAUS_API_KEY=...
MALWAREBAZAAR_API_KEY=...
VIRUSTOTAL_API_KEY=...
```

The abuse.ch keys (ThreatFox, URLhaus, MalwareBazaar) come from [auth.abuse.ch](https://auth.abuse.ch/). The VirusTotal key comes from a free [VirusTotal](https://www.virustotal.com/) account.

### 3. Load data

```bash
python -m scripts.sync_misp        # MISP events from CIRCL, Botvrij, Rösti
python -m ingestion.threatfox      # ThreatFox IOCs
python -m ingestion.urlhaus        # URLhaus IOCs
python -m ingestion.malwarebazaar  # MalwareBazaar samples
python -m ingestion.ctidigest      # CTIDigest reports
```

You can also start a sync from the dashboard, which calls `POST /api/sync/{feed}`.

### 4. Run

```bash
# Backend
uvicorn backend.app:app --reload

# Frontend (in a second terminal)
cd frontend
python -m http.server 5500
```

Open http://127.0.0.1:5500. The frontend calls `http://127.0.0.1:8000` by default. To point it at a deployed backend, set `window.CTI_API_BASE` before the page scripts load.

## Security note

API keys and the MongoDB connection string are read from `.env`, which is git-ignored. Never commit real keys.

## Author

**Harshit Sethiya**, B.Tech (AIML), Jain University
