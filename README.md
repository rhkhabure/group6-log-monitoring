# Group 6 — Centralized Log Monitoring
## DSA 4030: Big Data Security | USIU-Africa

> **Scenario:** An organization wants to monitor security events from multiple systems.

---

## 📐 Architecture Overview

```
[Source 1]              [Source 2]              [Source 3]
SSH Auth Logs           Web Server Logs         App Event Logs
ssh_logs.log            web_logs.log            app_logs.json
      |                       |                       |
      └───────────────────────┴───────────────────────┘
                              |
                    [ingest_logs.py]
               Python script reads all 3 files
               pushes directly to OpenSearch
               via Bulk REST API (port 9200)
                              |
                       [OpenSearch]
                  stores + indexes all events
                  114,500 records | port 9200
                              |
               [OpenSearch Dashboards]
               visual dashboard + alerts
               port 5601
```

> **Note on Filebeat:** The assignment suggests Filebeat as the log shipper.
> However, Filebeat 8.x has a hardcoded `/_license` compatibility check that
> OpenSearch 2.x rejects (400 Bad Request — `Invalid index name [_license]`).
> This is a known incompatibility with no config-level workaround in Filebeat 8.x.
> We replaced Filebeat with a Python ingestion script (`scripts/ingest_logs.py`)
> that talks directly to OpenSearch's Bulk REST API — same outcome, no middleware issues.

---

## 🧱 Tech Stack

| Tool | Version | Role |
|------|---------|------|
| Python | 3.x | Log generation (Part B) + log ingestion |
| Docker Desktop | Latest | Runs OpenSearch + Dashboards in containers |
| OpenSearch | 2.13.0 | Log storage, indexing, search |
| OpenSearch Dashboards | 2.13.0 | Visual dashboard (Kibana equivalent) |

---

## ⚙️ Prerequisites

Install these before cloning the repo:

- [ ] [Docker Desktop](https://www.docker.com/products/docker-desktop/) — must be **open and running**
- [ ] [Python 3.x](https://www.python.org/downloads/)
- [ ] [Git](https://git-scm.com/downloads)
- [ ] Minimum **8GB RAM** (OpenSearch needs ~4GB)
- [ ] Minimum **10GB free disk space**

> ⚠️ **Windows users:** Docker Desktop must use the WSL 2 backend.
> Check: Docker Desktop → Settings → General → "Use WSL 2 based engine" ✓
> This is the default for new installs.

---

## 🚀 Setup Instructions

Follow these steps **in order** every time you set up on a new machine.

### Step 1 — Clone the repository

```bash
git clone https://github.com/YOUR_USERNAME/group6-log-monitoring.git
cd group6-log-monitoring
```

### Step 2 — Install Python dependencies

```bash
pip install faker requests
```

Two libraries only:
- `faker` — generates realistic fake names, IPs, timestamps for the dataset
- `requests` — used by the ingestion script to talk to OpenSearch's REST API

### Step 3 — Generate the log files

```bash
python scripts/generate_logs.py
```

This creates three files in the `logs/` folder:

| File | Source | Records | Description |
|------|--------|---------|-------------|
| `logs/ssh_logs.log` | Source 1 | ~9,500 | SSH authentication log (mirrors `/var/log/auth.log`) |
| `logs/web_logs.log` | Source 2 | ~5,000 | Web server access log (Apache/Nginx format) |
| `logs/app_logs.json` | Source 3 | 100,000 | Application event log — **Part B dataset** |

Expected output:
```
[✓] SSH logs generated      → logs/ssh_logs.log   (9,500 lines)
[✓] Web server logs generated → logs/web_logs.log (5,000 lines)
[✓] Application logs generated → logs/app_logs.json (100,000 records)
```

> ⚠️ The `logs/` folder is in `.gitignore` — log files are generated locally
> on each machine, not stored in GitHub (they're too large and regeneratable).

### Step 4 — Start Docker

Make sure Docker Desktop is **open** first, then:

```bash
docker compose up -d
```

This pulls and starts two containers:
- `opensearch` — the log database (port 9200)
- `opensearch-dashboards` — the visual dashboard (port 5601)

**First run** downloads Docker images (~2GB). Takes a few minutes.
Subsequent starts are near-instant.

Wait about **30 seconds** after this command before moving to Step 5.

### Step 5 — Verify OpenSearch is ready

```bash
curl http://localhost:9200/_cluster/health
```

Look for `"status":"green"` or `"status":"yellow"` — either is fine.
Do NOT proceed to Step 6 until you see this.

### Step 6 — Ingest logs into OpenSearch

```bash
python scripts/ingest_logs.py
```

This reads all three log files and pushes them to OpenSearch in batches of 500.
Takes about 60–90 seconds for all 114,500 records.

Expected output:
```
[✓] OpenSearch is up — cluster status: green
[✓] Index ready: group6-logs-2026.07.16
[✓] Ssh logs done    →   9,500 records ingested
[✓] Web logs done    →   5,000 records ingested
[✓] App logs done    → 100,000 records ingested
TOTAL                → 114,500 records → index: group6-logs-2026.07.16
```

### Step 7 — Verify record count

```bash
curl http://localhost:9200/group6-logs-*/_count
```

Expected: `{"count":114500,...}`

### Step 8 — Open the Dashboard

Open your browser and go to:
```
http://localhost:5601
```

No login required (security disabled for project environment).

### Step 9 — Create the Index Pattern (first time only)

This step connects the dashboard to your data. Do it once per machine.

1. Click **☰ (hamburger menu)** top left
2. Scroll to **Management** → click **Dashboards Management**
3. Click **Index Patterns** → **Create index pattern**
4. Type `group6-logs-*` → click **Next step**
5. Select `timestamp` as the time field → click **Create index pattern**

### Step 10 — View your data in Discover

1. Click **☰** → **Discover**
2. Top right — change time range to **Last 90 days**
3. You should see 114,500 events with a histogram timeline

**Test filters** (paste into the search bar):
```
log_source: ssh_auth                    ← SSH events only
log_source: web_server                  ← Web server events only
log_source: application                 ← App events only
severity: CRITICAL                      ← Critical alerts only
alert_reason: AFTER_HOURS_ACCESS        ← After-hours logins (~8,000)
alert_reason: BRUTE_FORCE_ATTEMPT       ← Brute force attacks (~5,000)
alert_reason: LARGE_EXPORT_DETECTED     ← Data exfiltration (~4,000)
alert_reason: UNAUTHORIZED_ACCESS_ATTEMPT ← Privilege escalation (~2,000)
```

---

## 🛑 Stopping the Environment

```bash
docker compose down
```

Stops containers but **keeps your indexed data** in the Docker volume.
Next time just run `docker compose up -d` — no need to re-ingest.

**Full reset** (wipes all data, start completely fresh):
```bash
docker compose down -v
```
After a full reset you must re-run Steps 6–9.

---

## 📁 Project Structure

```
group6-log-monitoring/
│
├── docker-compose.yml          ← starts OpenSearch + Dashboards
├── scripts/
│   ├── generate_logs.py        ← Part B: generates all three log sources
│   └── ingest_logs.py          ← pushes logs to OpenSearch via Bulk API
├── logs/                       ← GENERATED LOCALLY — not in GitHub
│   ├── ssh_logs.log            ← Source 1 (~9,500 lines)
│   ├── web_logs.log            ← Source 2 (~5,000 lines)
│   └── app_logs.json           ← Source 3 / Part B dataset (100,000 records)
├── .gitignore
└── README.md
```

---

## 🔍 Log Sources & Dataset Details

### Source 1 — SSH Authentication Logs (`ssh_logs.log`)
Mirrors Linux `/var/log/auth.log` format.

| Event Type | Count | Description |
|-----------|-------|-------------|
| Successful logins | ~3,500 | Normal business-hours access |
| Failed logins | ~1,000 | Isolated authentication failures |
| Brute-force bursts | ~5,000 | Rapid-fire attacks from external IPs |

### Source 2 — Web Server Logs (`web_logs.log`)
Mirrors Apache/Nginx combined log format.

| Event Type | Count | Description |
|-----------|-------|-------------|
| Normal traffic | ~3,500 | Legitimate user browsing (200/301) |
| Attacker probing | ~1,500 | Scanner tools, suspicious endpoints (403/404) |

### Source 3 — Application Event Logs (`app_logs.json`) — Part B Dataset

| Event Type | Count | % | Severity |
|-----------|-------|---|----------|
| Normal logins | 45,000 | 45% | INFO |
| Normal data access | 35,000 | 35% | INFO |
| After-hours logins | 8,000 | 8% | WARNING |
| Brute-force attempts | 5,000 | 5% | CRITICAL |
| Large data exports | 4,000 | 4% | WARNING |
| Privilege escalation | 2,000 | 2% | CRITICAL |
| Other anomalies | 1,000 | 1% | WARNING |
| **TOTAL** | **100,000** | **100%** | |

---

## 🐛 Troubleshooting

**OpenSearch container exits immediately / won't start:**
- Increase Docker Desktop memory: Settings → Resources → Memory → set to 6GB+

**`docker compose` not found:**
- Try `docker-compose` (hyphen) — older Docker versions use this syntax

**Ingestion script says "Could not connect to OpenSearch":**
- Docker containers aren't ready yet. Wait 30 seconds and retry.
- Check containers are running: `docker compose ps`

**Dashboard shows "No results" in Discover:**
- Make sure time range is set to **Last 90 days** (default is Last 15 minutes)
- Check you created the index pattern with `group6-logs-*`

**Port 9200 or 5601 already in use:**
- Something else on your machine uses that port
- Change the port in `docker-compose.yml` e.g. `"9201:9200"` then update
  the OpenSearch URL in `scripts/ingest_logs.py` to match

**`pip install` fails:**
- Try `pip3 install faker requests`
- Or: `python -m pip install faker requests`

---

## 👥 Group Member Responsibilities

| Member | Part | Description |
|--------|------|-------------|
| Howard (Richard) | A + B | Environment setup + dataset generation |
| Arlen| C | Security controls implementation |
| Arlen| D | Security testing (minimum 6 tests) |
| | E | Vulnerabilities, risks, recommendations |
| | Deliverables | Executive summary + architecture diagram |

---

## 📋 Quick Reference — Common Commands

```bash
# Start environment
docker compose up -d

# Check containers are running
docker compose ps

# Check OpenSearch health
curl http://localhost:9200/_cluster/health

# Ingest logs
python scripts/ingest_logs.py

# Check record count
curl http://localhost:9200/group6-logs-*/_count

# View OpenSearch Dashboard
# Open browser → http://localhost:5601

# Stop environment (keeps data)
docker compose down

# Full reset (wipes all data)
docker compose down -v
```

---

*DSA 4030: Big Data Security — End of Semester Practical Group Project*
*United States International University — Africa*
