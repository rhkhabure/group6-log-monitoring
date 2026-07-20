"""
=============================================================
GROUP 6 - CENTRALIZED LOG MONITORING
DSA 4030: Big Data Security | USIU-Africa

Log Ingestion Script
---------------------
Replaces Filebeat. Reads all three log files and pushes them
directly to OpenSearch using the Bulk API.

Why not Filebeat?
  Filebeat 8.x has a hardcoded /_license compatibility check
  that OpenSearch 2.x rejects (400 Bad Request). This script
  bypasses that entirely by talking directly to OpenSearch's
  REST API — no middleware, no compatibility issues.

Requirements:
    pip install requests

Usage:
    python scripts/ingest_logs.py

Run AFTER: docker compose up -d
Run AFTER: python scripts/generate_logs.py
=============================================================
"""

import json
import requests
import os
import re
from datetime import datetime

# ── Config ────────────────────────────────────────────────────────────────────
OPENSEARCH_URL = "http://localhost:9200"
TODAY = datetime.now().strftime("%Y.%m.%d")
INDEX = f"group6-logs-{TODAY}"          # e.g. group6-logs-2026.07.16
BATCH_SIZE = 500                        # records per bulk request (sweet spot for speed)

LOG_FILES = {
    "logs/ssh_logs.log":  {"log_source": "ssh_auth",    "source_type": "authentication"},
    "logs/web_logs.log":  {"log_source": "web_server",  "source_type": "web_access"},
    "logs/app_logs.json": {"log_source": "application", "source_type": "app_events"},
}

# ── Helpers ───────────────────────────────────────────────────────────────────

def wait_for_opensearch():
    """Poll OpenSearch until it's ready."""
    print(f"[→] Connecting to OpenSearch at {OPENSEARCH_URL}...")
    for attempt in range(20):
        try:
            r = requests.get(f"{OPENSEARCH_URL}/_cluster/health", timeout=5)
            if r.status_code == 200:
                status = r.json().get("status", "unknown")
                print(f"[✓] OpenSearch is up — cluster status: {status}")
                return True
        except requests.exceptions.ConnectionError:
            pass
        print(f"    Waiting... (attempt {attempt + 1}/20)")
        import time; time.sleep(3)
    print("[✗] Could not connect to OpenSearch. Is Docker running?")
    return False


def create_index():
    """Create the index with basic mappings if it doesn't exist."""
    mappings = {
        "mappings": {
            "properties": {
                "timestamp":        {"type": "date",    "format": "yyyy-MM-dd'T'HH:mm:ss||dd/MMM/yyyy:HH:mm:ss Z||MMM dd HH:mm:ss"},
                "log_source":       {"type": "keyword"},
                "source_type":      {"type": "keyword"},
                "event_type":       {"type": "keyword"},
                "user_id":          {"type": "keyword"},
                "ip_address":       {"type": "ip",      "ignore_malformed": True},
                "department":       {"type": "keyword"},
                "status":           {"type": "keyword"},
                "severity":         {"type": "keyword"},
                "alert_reason":     {"type": "keyword"},
                "records_accessed": {"type": "integer"},
                "message":          {"type": "text"}
            }
        }
    }
    r = requests.put(
        f"{OPENSEARCH_URL}/{INDEX}",
        headers={"Content-Type": "application/json"},
        data=json.dumps(mappings),
        timeout=10
    )
    if r.status_code in (200, 400):  # 400 = already exists, that's fine
        print(f"[✓] Index ready: {INDEX}")
    else:
        print(f"[!] Index creation response: {r.status_code} — {r.text[:200]}")


def bulk_ingest(records):
    """Send a batch of records to OpenSearch using the Bulk API."""
    if not records:
        return 0

    # Bulk API format: action line + document line, alternating
    body = ""
    for record in records:
        action = json.dumps({"index": {"_index": INDEX}})
        doc    = json.dumps(record)
        body  += action + "\n" + doc + "\n"

    r = requests.post(
        f"{OPENSEARCH_URL}/_bulk",
        headers={"Content-Type": "application/x-ndjson"},
        data=body,
        timeout=30
    )

    if r.status_code == 200:
        result = r.json()
        errors = result.get("errors", False)
        if errors:
            # count actual failures
            failed = sum(1 for item in result["items"] if "error" in item.get("index", {}))
            return len(records) - failed
        return len(records)
    else:
        print(f"    [!] Bulk error {r.status_code}: {r.text[:300]}")
        return 0


def ingest_app_logs(filepath, extra_fields):
    """
    Ingest app_logs.json — each line is a complete JSON object.
    These are the richest records (100,000 of them).
    """
    print(f"\n[→] Ingesting application logs: {filepath}")
    batch   = []
    total   = 0
    skipped = 0

    with open(filepath, "r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
                record.update(extra_fields)       # add log_source and source_type
                batch.append(record)

                if len(batch) >= BATCH_SIZE:
                    sent   = bulk_ingest(batch)
                    total += sent
                    batch  = []
                    print(f"    Ingested {total:,} records...", end="\r")

            except json.JSONDecodeError:
                skipped += 1

    # flush remaining
    if batch:
        total += bulk_ingest(batch)

    print(f"[✓] App logs done       → {total:,} records ingested  ({skipped} skipped)")
    return total


def ingest_text_logs(filepath, extra_fields, log_type):
    """
    Ingest SSH and web server logs — plain text, one event per line.
    Each line becomes a document with a 'message' field plus metadata.
    """
    print(f"\n[→] Ingesting {log_type} logs: {filepath}")
    batch  = []
    total  = 0

    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            record = {"message": line}
            record.update(extra_fields)

            # ── Parse timestamp from SSH log lines ──
            # Format: "Jul 15 14:23:01 server sshd[1234]: ..."
            if log_type == "ssh":
                m = re.match(r'^(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})', line)
                if m:
                    try:
                        ts = datetime.strptime(
                            f"{datetime.now().year} {m.group(1).strip()}",
                            "%Y %b %d %H:%M:%S"
                        )
                        record["timestamp"] = ts.strftime("%Y-%m-%dT%H:%M:%S")
                    except ValueError:
                        record["timestamp"] = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")

                # flag failed attempts for easy filtering
                if "Failed password" in line:
                    record["event_type"] = "SSH_FAILED_LOGIN"
                    record["severity"]   = "WARNING"
                    if "invalid user" in line:
                        record["severity"] = "CRITICAL"
                elif "Accepted password" in line:
                    record["event_type"] = "SSH_SUCCESS_LOGIN"
                    record["severity"]   = "INFO"

                # extract IP address
                ip_match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)
                if ip_match:
                    record["ip_address"] = ip_match.group(1)

            # ── Parse web log lines ──
            # Format: "IP - - [date] "METHOD /path HTTP/1.1" STATUS SIZE "-" "UA""
            elif log_type == "web":
                web_pattern = re.match(
                    r'^(\S+)\s+-\s+-\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)\s+\S+"\s+(\d+)\s+(\d+)\s+"-"\s+"([^"]*)"',
                    line
                )
                if web_pattern:
                    ip, ts_raw, method, path, status, size, ua = web_pattern.groups()
                    try:
                        ts = datetime.strptime(ts_raw, "%d/%b/%Y:%H:%M:%S %z")
                        record["timestamp"] = ts.strftime("%Y-%m-%dT%H:%M:%S")
                    except ValueError:
                        record["timestamp"] = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")

                    record["ip_address"]  = ip
                    record["http_method"] = method
                    record["url_path"]    = path
                    record["http_status"] = int(status)
                    record["user_agent"]  = ua
                    record["event_type"]  = "WEB_REQUEST"

                    # classify severity based on status code and user agent
                    suspicious_uas = ["sqlmap", "nikto", "masscan", "nmap", "ZAP"]
                    if any(s.lower() in ua.lower() for s in suspicious_uas):
                        record["severity"]   = "CRITICAL"
                        record["alert_reason"] = "SCANNER_DETECTED"
                    elif int(status) in (403, 404) and int(status) != 200:
                        record["severity"]   = "WARNING"
                        record["alert_reason"] = "ACCESS_DENIED_OR_NOT_FOUND"
                    else:
                        record["severity"]   = "INFO"

            batch.append(record)

            if len(batch) >= BATCH_SIZE:
                sent   = bulk_ingest(batch)
                total += sent
                batch  = []
                print(f"    Ingested {total:,} records...", end="\r")

    if batch:
        total += bulk_ingest(batch)

    print(f"[✓] {log_type.capitalize()} logs done    → {total:,} records ingested")
    return total


# ── Main ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("\n" + "="*60)
    print("  GROUP 6 LOG INGESTION — DSA 4030 Big Data Security")
    print("="*60)

    # Step 1 — wait for OpenSearch
    if not wait_for_opensearch():
        exit(1)

    # Step 2 — create index with mappings
    create_index()

    # Step 3 — check log files exist
    for filepath in LOG_FILES:
        if not os.path.exists(filepath):
            print(f"[!] Missing: {filepath}")
            print("    Run 'python scripts/generate_logs.py' first.")
            exit(1)

    # Step 4 — ingest all three sources
    ssh_count = ingest_text_logs("logs/ssh_logs.log",  {"log_source": "ssh_auth",   "source_type": "authentication"}, "ssh")
    web_count = ingest_text_logs("logs/web_logs.log",  {"log_source": "web_server", "source_type": "web_access"},    "web")
    app_count = ingest_app_logs( "logs/app_logs.json", {"log_source": "application","source_type": "app_events"})

    # Step 5 — summary
    total = ssh_count + web_count + app_count
    print("\n" + "="*60)
    print("  INGESTION COMPLETE")
    print(f"  SSH logs    : {ssh_count:>8,} records")
    print(f"  Web logs    : {web_count:>8,} records")
    print(f"  App logs    : {app_count:>8,} records")
    print(f"  TOTAL       : {total:>8,} records → index: {INDEX}")
    print("="*60)
    print(f"\n[→] Open Kibana: http://localhost:5601")
    print(f"[→] Verify count: curl http://localhost:9200/{INDEX}/_count\n")