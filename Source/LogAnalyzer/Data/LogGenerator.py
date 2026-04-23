#!/usr/bin/env python3

import csv
import time
import random
from datetime import datetime, timedelta
from pathlib import Path

from openpyxl import Workbook

random.seed(42)

OUT_DIR = Path(".")
TXT_FILE = OUT_DIR / "Sample.txt"
LOG_FILE = OUT_DIR / "Sample.log"
CSV_FILE = OUT_DIR / "Sample.csv"
XLSX_FILE = OUT_DIR / "Sample.xlsx"

START_TIME = datetime(2026, 4, 1, 8, 0, 0)

ATTACK_IPS = ["185.77.44.10", "103.55.12.91", "45.13.201.7"]
NORMAL_IPS = ["192.168.1.20", "192.168.1.21", "10.0.0.15", "10.0.0.22", "172.16.0.8"]
USERNAMES = ["sajjid", "admin", "root", "backup", "dbadmin", "intern", "svc_web", "helpdesk"]

SUCCESS_TEMPLATES = [
    "Accepted password for {user} from {ip} port 22 ssh2",
    "login successful for {user} from {ip}",
    "session opened for user {user} from {ip}",
    "User {user} successfully logged in from {ip}",
]

FAILED_TEMPLATES = [
    "Failed password for invalid user {user} from {ip} port 22 ssh2",
    "authentication failed for {user} from {ip}",
    "login failed for {user} from {ip}",
    "Invalid user {user} from {ip}",
    "Access denied for {user} from {ip}",
]

SUSPICIOUS_TEMPLATES = [
    "unauthorized access attempt from {ip} targeting account {user}",
    "warning: exploit attempt detected from {ip} against {user}",
    "error: blocked malware payload from {ip}",
    "attack signature matched for {user} from {ip}",
    "admin privilege escalation denied for {user} from {ip}",
]

def classify_severity(message: str) -> str:
    lowered = message.lower()
    high_markers = [
        "unauthorized", "exploit", "attack", "malware", "payload",
        "root", "admin", "blocked", "denied", "authentication failed"
    ]
    medium_markers = ["warning", "invalid user", "failed login", "failed password", "error"]

    if any(marker in lowered for marker in high_markers):
        return "High"
    if any(marker in lowered for marker in medium_markers):
        return "Medium"
    return "Low"

def build_events(total_rows: int = 500):
    events = []
    current = START_TIME

    # Force brute-force candidates
    for i in range(24):
        ip = ATTACK_IPS[i % len(ATTACK_IPS)]
        user = random.choice(["root", "admin", "dbadmin"])
        msg = random.choice(FAILED_TEMPLATES).format(user=user, ip=ip)
        events.append({
            "timestamp": current.strftime("%Y-%m-%d %H:%M:%S"),
            "ip": ip,
            "username": user,
            "event_type": "FAIL",
            "severity": classify_severity(msg),
            "message": msg,
        })
        current += timedelta(minutes=1)

    while len(events) < total_rows:
        roll = random.random()

        if roll < 0.48:
            ip = random.choice(ATTACK_IPS + NORMAL_IPS)
            user = random.choice(USERNAMES)
            msg = random.choice(FAILED_TEMPLATES).format(user=user, ip=ip)
            event_type = "FAIL"
        elif roll < 0.74:
            ip = random.choice(NORMAL_IPS)
            user = random.choice(USERNAMES)
            msg = random.choice(SUCCESS_TEMPLATES).format(user=user, ip=ip)
            event_type = "SUCCESS"
        else:
            ip = random.choice(ATTACK_IPS + NORMAL_IPS)
            user = random.choice(USERNAMES)
            msg = random.choice(SUSPICIOUS_TEMPLATES).format(user=user, ip=ip)
            event_type = "ALERT"

        events.append({
            "timestamp": current.strftime("%Y-%m-%d %H:%M:%S"),
            "ip": ip,
            "username": user,
            "event_type": event_type,
            "severity": classify_severity(msg),
            "message": msg,
        })
        current += timedelta(minutes=random.randint(1, 5))

    return events

def write_txt(events):
    with TXT_FILE.open("w", encoding="utf-8") as f:
        for e in events:
            f.write(f"{e['timestamp']} {e['message']}\n")

def write_log(events):
    procs = ["sshd[2241]", "authsvc[881]", "kernel[1002]", "pam_unix[712]"]
    hosts = ["server1", "server2", "server3"]

    with LOG_FILE.open("w", encoding="utf-8") as f:
        for i, e in enumerate(events):
            ts = datetime.strptime(e["timestamp"], "%Y-%m-%d %H:%M:%S").strftime("%b %d %H:%M:%S")
            host = hosts[i % len(hosts)]
            proc = procs[i % len(procs)]
            f.write(f"{ts} {host} {proc}: {e['message']}\n")

def write_csv(events):
    with CSV_FILE.open("w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp", "ip", "username", "event_type", "severity", "message"])
        for e in events:
            writer.writerow([
                e["timestamp"],
                e["ip"],
                e["username"],
                e["event_type"],
                e["severity"],
                e["message"],
            ])

def write_xlsx(events):
    wb = Workbook()
    ws = wb.active
    ws.title = "SecurityLogs"
    ws.append(["timestamp", "ip", "username", "event_type", "severity", "message"])

    for e in events:
        ws.append([
            e["timestamp"],
            e["ip"],
            e["username"],
            e["event_type"],
            e["severity"],
            e["message"],
        ])

    wb.save(XLSX_FILE)

def main():
    events = build_events(500)
    write_txt(events)
    write_log(events)
    write_csv(events)
    write_xlsx(events)

    print("Created files:")
    print(f" - {TXT_FILE.resolve()}")
    print(f" - {LOG_FILE.resolve()}")
    print(f" - {CSV_FILE.resolve()}")
    print(f" - {XLSX_FILE.resolve()}")
    print(f"Rows/events per file: {len(events)}")

if __name__ == "__main__":
    main()
    time.sleep(15)
