"""
=============================================================
GROUP 6 - CENTRALIZED LOG MONITORING
DSA 4030: Big Data Security
USIU-Africa

Log Generator Script
---------------------
This script generates three types of simulated security logs:
  1. SSH Authentication Logs  (Source 1) → logs/ssh_logs.log
  2. Web Server Access Logs   (Source 2) → logs/web_logs.log
  3. Application Event Logs   (Source 3) → logs/app_logs.json  ← Part B dataset (100,000+ records)

Run this script ONCE before starting Docker.
Filebeat will then pick up all three log files and ship them to OpenSearch.

Requirements:
    pip install faker

Usage:
    python scripts/generate_logs.py
=============================================================
"""

import json
import random
import os
from datetime import datetime, timedelta
from faker import Faker

# ── initialise Faker for realistic fake data ──────────────────────────────────
fake = Faker()
random.seed(42)          # fixed seed → same output every run → reproducible

# ── output paths ──────────────────────────────────────────────────────────────
os.makedirs("logs", exist_ok=True)   # create logs/ folder if it doesn't exist

SSH_LOG_FILE = "logs/ssh_logs.log"
WEB_LOG_FILE = "logs/web_logs.log"
APP_LOG_FILE = "logs/app_logs.json"

# =============================================================================
# SHARED CONFIG — users, IPs, departments used across all three log types
# =============================================================================

# Legitimate internal users (normal employees)
NORMAL_USERS = [
    "alice.kamau", "brian.otieno", "carol.wanjiku", "david.mwangi",
    "emily.achieng", "frank.njoroge", "grace.mutua", "henry.odhiambo",
    "irene.waweru", "james.kimani", "kevin.omondi", "linda.ndung'u",
    "mary.mugo", "nicholas.gitau", "olivia.wangari", "peter.karanja"
]

# Suspicious / attacker accounts
SUSPICIOUS_USERS = [
    "admin", "root", "test_user", "backup_admin",
    "alice.kamau",   # legitimate user behaving suspiciously (insider threat)
    "brian.otieno",  # legitimate user behaving suspiciously (insider threat)
]

# Internal IP addresses (company network 192.168.1.x)
INTERNAL_IPS = [f"192.168.1.{i}" for i in range(10, 60)]

# External / attacker IP addresses
EXTERNAL_IPS = [
    "45.33.32.156", "198.20.70.114", "89.248.167.131",
    "103.41.167.234", "185.220.101.45", "194.165.16.11",
    "23.129.64.131", "171.25.193.77", "80.67.172.162"
]

# Departments in the simulated organisation
DEPARTMENTS = ["HR", "FINANCE", "MEDICAL", "IT", "OPERATIONS", "LEGAL"]

# Web endpoints that legitimate users hit
NORMAL_ENDPOINTS = [
    "/dashboard", "/reports", "/profile", "/search",
    "/api/data", "/api/users", "/login", "/logout", "/help"
]

# Endpoints that attackers typically probe
SUSPICIOUS_ENDPOINTS = [
    "/admin", "/wp-login.php", "/phpmyadmin", "/.env",
    "/api/admin", "/config", "/../../../etc/passwd",
    "/shell.php", "/backup.zip", "/.git/config"
]

# HTTP methods
HTTP_METHODS = ["GET", "POST", "PUT", "DELETE"]

# ── helper: generate a random timestamp ──────────────────────────────────────
def random_timestamp(days_back=30, hour_min=8, hour_max=18, force_hour=None):
    """
    Returns a datetime object within the last `days_back` days.
    hour_min / hour_max define the working-hours window for normal activity.
    force_hour overrides the hour (used for after-hours suspicious events).
    """
    base = datetime.now() - timedelta(days=random.randint(0, days_back))
    if force_hour is not None:
        hour = force_hour
    else:
        hour = random.randint(hour_min, hour_max)
    minute = random.randint(0, 59)
    second = random.randint(0, 59)
    return base.replace(hour=hour, minute=minute, second=second, microsecond=0)


# =============================================================================
# SOURCE 1 — SSH AUTHENTICATION LOGS
# Format mirrors real Linux /var/log/auth.log entries
# Target: ~5,000 lines  (mix of successful logins, failures, brute-force)
# =============================================================================

def generate_ssh_logs(n_normal=3500, n_failed=1000, n_bruteforce=500):
    """
    Generates simulated SSH authentication log lines.

    n_normal     → successful logins during working hours (normal behaviour)
    n_failed     → isolated failed login attempts
    n_bruteforce → rapid-fire failed attempts from one IP (attack pattern)
    """
    lines = []

    # ── normal successful logins ──────────────────────────────────────────────
    for _ in range(n_normal):
        ts   = random_timestamp(hour_min=8, hour_max=18)
        user = random.choice(NORMAL_USERS)
        ip   = random.choice(INTERNAL_IPS)
        port = random.randint(50000, 65000)
        line = (
            f"{ts.strftime('%b %d %H:%M:%S')} server sshd[{random.randint(1000,9999)}]: "
            f"Accepted password for {user} from {ip} port {port} ssh2"
        )
        lines.append((ts, line))

    # ── isolated failed logins ────────────────────────────────────────────────
    for _ in range(n_failed):
        ts   = random_timestamp()           # any time of day
        user = random.choice(SUSPICIOUS_USERS + NORMAL_USERS)
        ip   = random.choice(EXTERNAL_IPS + INTERNAL_IPS)
        port = random.randint(50000, 65000)
        line = (
            f"{ts.strftime('%b %d %H:%M:%S')} server sshd[{random.randint(1000,9999)}]: "
            f"Failed password for {'invalid user ' if user in ['admin','root','test_user'] else ''}"
            f"{user} from {ip} port {port} ssh2"
        )
        lines.append((ts, line))

    # ── brute-force bursts (many failures from one IP in quick succession) ────
    for _ in range(n_bruteforce):
        base_ts  = random_timestamp(days_back=7)
        attacker = random.choice(EXTERNAL_IPS)
        # each burst: 10 rapid attempts within a few seconds
        for i in range(10):
            ts   = base_ts + timedelta(seconds=i)
            user = random.choice(["admin", "root", "ubuntu", "pi"])
            port = random.randint(50000, 65000)
            line = (
                f"{ts.strftime('%b %d %H:%M:%S')} server sshd[{random.randint(1000,9999)}]: "
                f"Failed password for invalid user {user} from {attacker} port {port} ssh2"
            )
            lines.append((ts, line))

    # sort chronologically so logs read naturally
    lines.sort(key=lambda x: x[0])

    with open(SSH_LOG_FILE, "w") as f:
        for _, line in lines:
            f.write(line + "\n")

    total = len(lines)
    print(f"[✓] SSH logs generated     → {SSH_LOG_FILE}  ({total:,} lines)")
    return total


# =============================================================================
# SOURCE 2 — WEB SERVER ACCESS LOGS
# Format mirrors real Apache/Nginx combined log format
# Target: ~5,000 lines  (normal browsing + attacker probing)
# =============================================================================

def generate_web_logs(n_normal=3500, n_suspicious=1500):
    """
    Generates simulated Apache/Nginx-style access log lines.

    n_normal     → legitimate user browsing during business hours
    n_suspicious → attacker probing for vulnerabilities (404s, 403s, scanners)
    """
    lines = []

    # ── normal web traffic ────────────────────────────────────────────────────
    for _ in range(n_normal):
        ts       = random_timestamp(hour_min=8, hour_max=18)
        ip       = random.choice(INTERNAL_IPS)
        method   = random.choices(HTTP_METHODS, weights=[60, 25, 10, 5])[0]
        endpoint = random.choice(NORMAL_ENDPOINTS)
        status   = random.choices([200, 201, 204, 301, 302], weights=[70,5,5,10,10])[0]
        size     = random.randint(200, 15000)
        ua       = fake.user_agent()
        ts_str   = ts.strftime("%d/%b/%Y:%H:%M:%S +0000")
        line = (
            f'{ip} - - [{ts_str}] "{method} {endpoint} HTTP/1.1" {status} {size} '
            f'"-" "{ua}"'
        )
        lines.append((ts, line))

    # ── suspicious/attacker traffic ───────────────────────────────────────────
    for _ in range(n_suspicious):
        # attackers often probe at night
        hour = random.choice(list(range(0, 6)) + list(range(22, 24)))
        ts       = random_timestamp(force_hour=hour)
        ip       = random.choice(EXTERNAL_IPS)
        method   = random.choice(["GET", "POST"])
        endpoint = random.choice(SUSPICIOUS_ENDPOINTS)
        status   = random.choices([403, 404, 500, 200], weights=[40, 40, 10, 10])[0]
        size     = random.randint(100, 2000)
        # attackers often use automated tools as user-agent
        ua       = random.choice([
            "sqlmap/1.7", "Nikto/2.1.6", "masscan/1.0",
            "python-requests/2.28", "curl/7.88.1", "Nmap Scripting Engine"
        ])
        ts_str   = ts.strftime("%d/%b/%Y:%H:%M:%S +0000")
        line = (
            f'{ip} - - [{ts_str}] "{method} {endpoint} HTTP/1.1" {status} {size} '
            f'"-" "{ua}"'
        )
        lines.append((ts, line))

    lines.sort(key=lambda x: x[0])

    with open(WEB_LOG_FILE, "w") as f:
        for _, line in lines:
            f.write(line + "\n")

    total = len(lines)
    print(f"[✓] Web server logs generated → {WEB_LOG_FILE}  ({total:,} lines)")
    return total


# =============================================================================
# SOURCE 3 — APPLICATION EVENT LOGS  (Part B dataset — 100,000 records)
# Format: JSON (one object per line — "JSON Lines" format)
# These represent events inside a fictional internal business application
# =============================================================================

# Breakdown of the 100,000 records (matches the plan):
#   Normal login events          → 45,000   (45%)
#   Normal data access events    → 35,000   (35%)
#   After-hours suspicious logins→  8,000   ( 8%)
#   Brute-force failed logins    →  5,000   ( 5%)
#   Large data exports           →  4,000   ( 4%)
#   Privilege escalation attempts→  2,000   ( 2%)
#   Other suspicious activity    →  1,000   ( 1%)
#                                  -------
#   TOTAL                        → 100,000  (100%)

def make_event(event_type, user, ip, dept, ts, **extra):
    """
    Builds one JSON log record.
    All records share the same base fields; extra kwargs add event-specific fields.
    """
    record = {
        "timestamp":    ts.strftime("%Y-%m-%dT%H:%M:%S"),   # ISO 8601 — OpenSearch handles this natively
        "event_type":   event_type,
        "user_id":      user,
        "ip_address":   ip,
        "department":   dept,
        "log_source":   "app_server_01",
    }
    record.update(extra)        # merge in any extra fields
    return record


def generate_app_logs():
    """
    Generates the full 100,000-record application event log dataset.
    Writes to logs/app_logs.json in JSON Lines format (one JSON object per line).
    Filebeat reads this file and ships each line as a separate event to OpenSearch.
    """
    records = []

    # ── 1. NORMAL LOGIN EVENTS (45,000) ──────────────────────────────────────
    # Pattern: known user, internal IP, business hours (08:00–18:00), SUCCESS
    print("   Generating normal logins...          (45,000)")
    for _ in range(45000):
        user = random.choice(NORMAL_USERS)
        ip   = random.choice(INTERNAL_IPS)
        dept = random.choice(DEPARTMENTS)
        ts   = random_timestamp(hour_min=8, hour_max=18)
        records.append(make_event(
            event_type = "LOGIN",
            user       = user,
            ip         = ip,
            dept       = dept,
            ts         = ts,
            status     = "SUCCESS",
            severity   = "INFO",
            records_accessed = 0
        ))

    # ── 2. NORMAL DATA ACCESS EVENTS (35,000) ────────────────────────────────
    # Pattern: known user, internal IP, business hours, small record counts
    print("   Generating normal data access...     (35,000)")
    for _ in range(35000):
        user = random.choice(NORMAL_USERS)
        ip   = random.choice(INTERNAL_IPS)
        dept = random.choice(DEPARTMENTS)
        ts   = random_timestamp(hour_min=8, hour_max=18)
        records.append(make_event(
            event_type       = "DATA_ACCESS",
            user             = user,
            ip               = ip,
            dept             = dept,
            ts               = ts,
            status           = "SUCCESS",
            severity         = "INFO",
            records_accessed = random.randint(1, 499)   # small, normal amount
        ))

    # ── 3. AFTER-HOURS SUSPICIOUS LOGINS (8,000) ─────────────────────────────
    # Pattern: known user, outside business hours (22:00–05:00), sometimes external IP
    # This directly matches the Group 6 scenario: "employees accessing data outside working hours"
    print("   Generating after-hours logins...     ( 8,000)")
    for _ in range(8000):
        user = random.choice(NORMAL_USERS)   # legitimate user — insider threat
        ip   = random.choice(INTERNAL_IPS + EXTERNAL_IPS)
        dept = random.choice(DEPARTMENTS)
        # force after-hours timestamp
        hour = random.choice(list(range(0, 6)) + list(range(22, 24)))
        ts   = random_timestamp(force_hour=hour)
        records.append(make_event(
            event_type = "LOGIN",
            user       = user,
            ip         = ip,
            dept       = dept,
            ts         = ts,
            status     = "SUCCESS",
            severity   = "WARNING",                     # flagged as warning
            records_accessed = 0,
            alert_reason = "AFTER_HOURS_ACCESS"
        ))

    # ── 4. BRUTE-FORCE FAILED LOGINS (5,000) ─────────────────────────────────
    # Pattern: external IP, rapid repeated failures, targeting generic usernames
    print("   Generating brute-force attempts...   ( 5,000)")
    for _ in range(5000):
        user = random.choice(["admin", "root", "test", "administrator", "sa"])
        ip   = random.choice(EXTERNAL_IPS)
        dept = "UNKNOWN"
        ts   = random_timestamp()
        records.append(make_event(
            event_type   = "LOGIN",
            user         = user,
            ip           = ip,
            dept         = dept,
            ts           = ts,
            status       = "FAILED",
            severity     = "CRITICAL",
            records_accessed = 0,
            alert_reason = "BRUTE_FORCE_ATTEMPT"
        ))

    # ── 5. LARGE DATA EXPORTS (4,000) ────────────────────────────────────────
    # Pattern: known user accessing unusually large number of records in one session
    # Classic data exfiltration indicator
    print("   Generating large data exports...     ( 4,000)")
    for _ in range(4000):
        user = random.choice(NORMAL_USERS)
        ip   = random.choice(INTERNAL_IPS)
        dept = random.choice(DEPARTMENTS)
        ts   = random_timestamp()
        records.append(make_event(
            event_type       = "DATA_EXPORT",
            user             = user,
            ip               = ip,
            dept             = dept,
            ts               = ts,
            status           = "SUCCESS",
            severity         = "WARNING",
            records_accessed = random.randint(10000, 150000),   # suspiciously large
            alert_reason     = "LARGE_EXPORT_DETECTED"
        ))

    # ── 6. PRIVILEGE ESCALATION ATTEMPTS (2,000) ─────────────────────────────
    # Pattern: normal user attempting to access admin functions or other departments
    print("   Generating privilege escalation...   ( 2,000)")
    for _ in range(2000):
        user = random.choice(NORMAL_USERS)
        ip   = random.choice(INTERNAL_IPS)
        # user tries to access a department they're NOT assigned to
        all_depts     = DEPARTMENTS.copy()
        user_dept     = random.choice(all_depts)
        all_depts.remove(user_dept)
        target_dept   = random.choice(all_depts)
        ts            = random_timestamp()
        records.append(make_event(
            event_type       = "PRIVILEGE_ESCALATION",
            user             = user,
            ip               = ip,
            dept             = user_dept,
            ts               = ts,
            status           = "BLOCKED",
            severity         = "CRITICAL",
            records_accessed = 0,
            target_resource  = f"{target_dept}_ADMIN_PANEL",
            alert_reason     = "UNAUTHORIZED_ACCESS_ATTEMPT"
        ))

    # ── 7. OTHER SUSPICIOUS ACTIVITY (1,000) ─────────────────────────────────
    # Pattern: mix of anomalies — odd user agents, impossible travel, etc.
    print("   Generating other suspicious events...( 1,000)")
    for _ in range(1000):
        user = random.choice(NORMAL_USERS)
        ip   = random.choice(EXTERNAL_IPS)
        dept = random.choice(DEPARTMENTS)
        ts   = random_timestamp()
        records.append(make_event(
            event_type       = "ANOMALY",
            user             = user,
            ip               = ip,
            dept             = dept,
            ts               = ts,
            status           = "FLAGGED",
            severity         = "WARNING",
            records_accessed = random.randint(0, 5000),
            alert_reason     = random.choice([
                "IMPOSSIBLE_TRAVEL",
                "UNKNOWN_DEVICE",
                "SUSPICIOUS_USER_AGENT",
                "MULTIPLE_SESSION_DETECTED"
            ])
        ))

    # ── shuffle so records aren't in neat blocks, then sort by timestamp ──────
    random.shuffle(records)
    records.sort(key=lambda r: r["timestamp"])

    # ── write to file (JSON Lines format — one JSON object per line) ──────────
    with open(APP_LOG_FILE, "w") as f:
        for record in records:
            f.write(json.dumps(record) + "\n")

    total = len(records)
    print(f"\n[✓] Application logs generated → {APP_LOG_FILE}  ({total:,} records)")
    return total


# =============================================================================
# MAIN — run all three generators
# =============================================================================

if __name__ == "__main__":
    print("\n" + "="*60)
    print("  GROUP 6 LOG GENERATOR — DSA 4030 Big Data Security")
    print("="*60 + "\n")

    print("[1/3] Generating SSH authentication logs...")
    ssh_count = generate_ssh_logs()

    print("\n[2/3] Generating web server access logs...")
    web_count = generate_web_logs()

    print("\n[3/3] Generating application event logs (Part B dataset)...")
    app_count = generate_app_logs()

    print("\n" + "="*60)
    print("  GENERATION COMPLETE")
    print(f"  SSH logs   : {ssh_count:>8,} lines  → {SSH_LOG_FILE}")
    print(f"  Web logs   : {web_count:>8,} lines  → {WEB_LOG_FILE}")
    print(f"  App logs   : {app_count:>8,} records → {APP_LOG_FILE}")
    print(f"  TOTAL      : {ssh_count + web_count + app_count:>8,} events")
    print("="*60)
    print("\n[→] All log files are in the logs/ folder.")
    print("[→] Start Docker next:  docker compose up -d")
    print("[→] Then open Kibana:   http://localhost:5601\n")