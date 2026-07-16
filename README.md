# Group 6 — Centralized Log Monitoring
## DSA 4030: Big Data Security | USIU-Africa

> **Scenario:** An organization wants to monitor security events from multiple systems.

---

## 📐 Architecture Overview

```
[Source 1]            [Source 2]            [Source 3]
SSH Auth Logs         Web Server Logs       App Event Logs
ssh_logs.log          web_logs.log          app_logs.json
      |                     |                     |
      └─────────────────────┴─────────────────────┘
                            |
                       [Filebeat]
                  reads all 3 log files,
                  ships events to OpenSearch
                            |
                      [OpenSearch]
                  stores + indexes all events
                  port 9200
                            |
                  [OpenSearch Dashboards]
                  visual dashboard + alerts
                  port 5601
```

---

## 🧱 Tech Stack

| Tool | Version | Role |
|------|---------|------|
| Python | 3.x | Log generator (Part B dataset) |
| Docker Desktop | Latest | Runs all services in containers |
| OpenSearch | 2.13.0 | Log storage and indexing |
| OpenSearch Dashboards | 2.13.0 | Visual dashboard (Kibana equivalent) |
| Filebeat | 8.13.0 | Ships logs from files to OpenSearch |

---

## ⚙️ Prerequisites (install these before cloning)

- [ ] [Docker Desktop](https://www.docker.com/products/docker-desktop/) — **must be running** when you start the project
- [ ] [Python 3.x](https://www.python.org/downloads/) — needed to generate log files
- [ ] [Git](https://git-scm.com/downloads) — needed to clone the repo
- [ ] **Minimum 8GB RAM** on your machine (OpenSearch needs at least 4GB)
- [ ] **Minimum 10GB free disk space**

> ⚠️ **Windows users:** Make sure Docker Desktop is set to use WSL 2 backend (Settings → General → Use WSL 2 based engine). This is the default for new installs.

---

## 🚀 Setup Instructions (follow in order)

### Step 1 — Clone the repository

```bash
git clone https://github.com/YOUR_USERNAME/group6-log-monitoring.git
cd group6-log-monitoring
```

### Step 2 — Install Python dependency

```bash
pip install faker
```

This is the only Python library needed. It generates realistic fake names, IPs, and timestamps.

### Step 3 — Generate the log files

```bash
python scripts/generate_logs.py
```

This creates three files inside the `logs/` folder:
- `logs/ssh_logs.log` — ~5,000 SSH authentication log lines (Source 1)
- `logs/web_logs.log` — ~5,000 web server access log lines (Source 2)
- `logs/app_logs.json` — **100,000 application event records** (Source 3 / Part B dataset)

Expected output:
```
[✓] SSH logs generated       → logs/ssh_logs.log   (5,000 lines)
[✓] Web server logs generated → logs/web_logs.log  (5,000 lines)
[✓] Application logs generated → logs/app_logs.json (100,000 records)
```

> ⚠️ The `logs/` folder is in `.gitignore` — log files are generated locally on each machine, NOT pushed to GitHub.

### Step 4 — Start the Docker environment

Make sure Docker Desktop is **open and running** first, then:

```bash
docker compose up -d
```

This downloads and starts three containers:
- `opensearch` — the log database
- `opensearch-dashboards` — the visual dashboard
- `filebeat` — the log shipper

First run downloads Docker images (~2GB total). This takes a few minutes depending on internet speed. Subsequent starts are instant.

### Step 5 — Verify everything is running

Check container status:
```bash
docker compose ps
```

All three containers should show `running`. Example output:
```
NAME                     STATUS          PORTS
opensearch               running         0.0.0.0:9200->9200/tcp
opensearch-dashboards    running         0.0.0.0:5601->5601/tcp
filebeat                 running
```

### Step 6 — Verify OpenSearch is receiving data

Open a browser and go to:
```
http://localhost:9200/group6-logs-*/_count
```

You should see a response like:
```json
{"count": 110000, "_shards": {...}}
```

If `count` is greater than 0, logs are flowing. ✅

### Step 7 — Open the Dashboard

Open a browser and go to:
```
http://localhost:5601
```

No login required (security is disabled for this project environment).

Navigate to: **Menu → Discover** to see all incoming log events.

---

## 🛑 Stopping the Environment

```bash
docker compose down
```

This stops all containers but **keeps your indexed data** (stored in Docker volume `opensearch-data`).

To stop AND delete all data (full reset):
```bash
docker compose down -v
```

---

## 📁 Project Structure

```
group6-log-monitoring/
│
├── docker-compose.yml          ← defines all Docker services
├── filebeat/
│   └── filebeat.yml            ← Filebeat configuration
├── logs/                       ← GENERATED LOCALLY (not in GitHub)
│   ├── ssh_logs.log            ← Source 1: SSH auth logs
│   ├── web_logs.log            ← Source 2: Web server logs
│   └── app_logs.json           ← Source 3 + Part B: App event logs (100,000 records)
├── scripts/
│   └── generate_logs.py        ← Part B dataset generator
├── .gitignore
└── README.md
```

---

## 🔍 Log Sources Summary

### Source 1 — SSH Authentication Logs (`ssh_logs.log`)
Mirrors the format of Linux `/var/log/auth.log`. Contains:
- Successful logins during business hours (normal)
- Isolated failed login attempts
- Brute-force attack bursts (rapid failures from one IP)

### Source 2 — Web Server Logs (`web_logs.log`)
Mirrors Apache/Nginx combined log format. Contains:
- Normal user browsing (200/301 responses)
- Attacker probing suspicious endpoints (403/404 with scanner user-agents)

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

**OpenSearch won't start / exits immediately:**
- Increase Docker Desktop memory to at least 6GB: Docker Desktop → Settings → Resources → Memory

**`docker compose` command not found:**
- Try `docker-compose` (with hyphen) instead — older Docker versions use this

**Filebeat shows errors about permissions:**
- The `filebeat.yml` already includes `-strict.perms=false` to handle this on Windows

**Dashboard shows "No data" in Discover:**
- Wait 2-3 minutes after starting containers for Filebeat to finish shipping all 100,000 records
- Check Filebeat logs: `docker compose logs filebeat`

**Port 9200 or 5601 already in use:**
- Something else on your machine is using that port. Stop it, or change the port mapping in `docker-compose.yml` (e.g. `"9201:9200"`)

---

## 👥 Group Member Responsibilities

| Member | Part | Description |
|--------|------|-------------|
| Howard | A + B | Environment setup + dataset generation (this repo) |
| [Name] | C | Security controls implementation |
| [Name] | D | Security testing (6 tests) |
| [Name] | E | Recommendations report |
| [Name] | Deliverables | Executive summary + architecture diagram |

---

*DSA 4030: Big Data Security — End of Semester Group Project*
*United States International University — Africa*
