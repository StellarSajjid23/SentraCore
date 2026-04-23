#!/usr/bin/env python3

import re
import time
import sys
import ipaddress
from collections import Counter, defaultdict

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    from colorama import init as colorama_init
    colorama_init()
except ImportError:
    pass


# =========================
# COLORS
# =========================
class Colors:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    MAGENTA = "\033[95m"
    BOLD = "\033[1m"
    RESET = "\033[0m"


# =========================
# RULE DEFINITIONS
# =========================
FAILED_PATTERNS = [
    r"failed password", r"authentication failed", r"login failed",
    r"invalid user", r"failed login", r"access denied", r"unauthorized"
]

SUCCESS_PATTERNS = [
    r"accepted password", r"login successful", r"session opened",
    r"successfully logged in", r"authentication success", r"logged in"
]

SUSPICIOUS_PATTERNS = [
    r"unauthorized", r"exploit", r"attack", r"malware", r"payload",
    r"blocked", r"privilege escalation", r"admin", r"root",
    r"security alert", r"warning", r"powershell", r"cmd\.exe",
    r"mimikatz", r"ransom", r"certutil", r"mshta", r"regsvr32",
    r"downloadstring", r"vssadmin", r"shadow copies"
]

USERNAME_PATTERNS = [
    r"for invalid user ([a-zA-Z0-9._-]+)",
    r"for user ([a-zA-Z0-9._-]+)",
    r"for ([a-zA-Z0-9._-]+) from",
    r"user[:= ]+([a-zA-Z0-9._-]+)",
    r"account[:= ]+([a-zA-Z0-9._-]+)",
    r"username[:= ]+([a-zA-Z0-9._-]+)",
]

PRIVILEGED_USERS = {"root", "admin", "administrator", "dbadmin", "sapadm", "oracle", "sys", "postgres"}

RULE_METADATA = {
    "IDENTITY_COMPROMISE_SUSPECTED": {
        "severity": "High",
        "tactic": "Credential Access",
        "description": "Repeated failures followed by a success from the same source."
    },
    "PASSWORD_SPRAY_SEQUENCE": {
        "severity": "High",
        "tactic": "Credential Access",
        "description": "One source targets many accounts with repeated failures."
    },
    "PRIVILEGED_ACCESS_ATTACK": {
        "severity": "High",
        "tactic": "Privilege Escalation",
        "description": "Repeated targeting of privileged accounts."
    },
    "AUTH_FAILURE_SPIKE": {
        "severity": "Medium",
        "tactic": "Credential Access",
        "description": "Large concentration of authentication failures from one source."
    },
    "SUSPICIOUS_SOURCE_AGGREGATION": {
        "severity": "High",
        "tactic": "Defense Evasion",
        "description": "Same source generated multiple suspicious behaviors."
    },
    "MALICIOUS_TOOLING_ACTIVITY": {
        "severity": "High",
        "tactic": "Execution",
        "description": "Evidence of attacker tooling or malicious execution strings."
    },
    "EXTERNAL_MULTI_ALERT_SOURCE": {
        "severity": "Medium",
        "tactic": "Command and Control",
        "description": "Public IP source generated multiple independent alert types."
    },
    "PERSISTENCE_OR_IMPACT_SIGNAL": {
        "severity": "High",
        "tactic": "Persistence/Impact",
        "description": "Persistence or ransomware-style activity detected."
    }
}


# =========================
# OUTPUT HELPERS
# =========================
def print_message(message: str):
    print(message + Colors.RESET)


def ask_input(prompt: str) -> str:
    return input(Colors.YELLOW + prompt + Colors.RESET)


# =========================
# BANNER
# =========================
def print_banner():
    banner = r"""

        +----------------------------------------------------------------+
        |          __  __ _       _   _____ _____ ______ __  __          |
        |         |  \/  (_)     (_) / ____|_   _|  ____|  \/  |         |
        |         | \  / |_ _ __  _ | (___   | | | |__  | \  / |         |
        |         | |\/| | | '_ \| | \___ \  | | |  __| | |\/| |         |
        |         | |  | | | | | | | ____) |_| |_| |____| |  | |         |
        |         |_|  |_|_|_| |_|_||_____/|_____|______|_|  |_|         |
        |                                                                |
        +----------------------------------------------------------------+
        |              Correlation and Alerting Engine                   |
        +----------------------------------------------------------------+
        
"""
    print(Colors.RED + banner + Colors.RESET)
    print(Colors.CYAN + "[*] Internship Portfolio Edition" + Colors.RESET)
    print(Colors.GREEN + "[*] Author: StellarSajjid23" + Colors.RESET)
    print(Colors.YELLOW + "[*] Engine: Correlated Detection and Alert Storylining" + Colors.RESET)
    print("                                                                  ")


# =========================
# HELPERS
# =========================
def load_log_file(file_path: str) -> list:
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as file:
            return [line.strip() for line in file if line.strip()]
    except Exception as exc:
        print_message(Colors.RED + f"[!] Failed to read file: {exc}")
        sys.exit(1)


def extract_ip(line: str) -> str:
    match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", line)
    return match.group(0) if match else "Unknown"


def extract_username(line: str) -> str:
    for pattern in USERNAME_PATTERNS:
        match = re.search(pattern, line, re.IGNORECASE)
        if match:
            return match.group(1)
    return "Unknown"


def extract_timestamp(line: str) -> str:
    patterns = [
        r"\b(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\b",
        r"\b(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\b",
        r"\b([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\b",
        r"\b(\d{1,2}/\d{1,2}/\d{4}\s+\d{1,2}:\d{2}(:\d{2})?)\b",
    ]
    for pattern in patterns:
        match = re.search(pattern, line)
        if match:
            return match.group(1)
    return "Unknown"


def is_failed_login(line: str) -> bool:
    lowered = line.lower()
    return any(re.search(pattern, lowered) for pattern in FAILED_PATTERNS)


def is_successful_login(line: str) -> bool:
    lowered = line.lower()
    return any(re.search(pattern, lowered) for pattern in SUCCESS_PATTERNS)


def is_suspicious(line: str) -> bool:
    lowered = line.lower()
    return any(re.search(pattern, lowered) for pattern in SUSPICIOUS_PATTERNS)


def is_public_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def get_geoip(ip: str) -> dict:
    result = {
        "country": "Unknown",
        "city": "Unknown",
        "isp": "Unknown",
        "note": "Unavailable"
    }

    if not is_public_ip(ip):
        result["note"] = "Private/Internal"
        return result

    if not REQUESTS_AVAILABLE:
        result["note"] = "requests missing"
        return result

    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=4)
        data = response.json()
        if data.get("status") == "success":
            result["country"] = data.get("country", "Unknown")
            result["city"] = data.get("city", "Unknown")
            result["isp"] = data.get("isp", "Unknown")
            result["note"] = "Success"
        else:
            result["note"] = "Lookup Failed"
    except Exception:
        result["note"] = "Lookup Failed"

    return result


def alert_confidence(rule_name: str, context: dict) -> str:
    score = 0

    if context.get("count", 0) >= 5:
        score += 1
    if context.get("count", 0) >= 10:
        score += 1
    if context.get("success_count", 0) >= 1:
        score += 1
    if context.get("distinct_users", 0) >= 3:
        score += 1
    if context.get("public_ip", False):
        score += 1
    if context.get("privileged", False):
        score += 1

    if rule_name in {"MALICIOUS_TOOLING_ACTIVITY", "PERSISTENCE_OR_IMPACT_SIGNAL"}:
        score += 1

    if score >= 5:
        return "High"
    if score >= 3:
        return "Medium"
    return "Low"


def alert_priority(severity: str, confidence: str, public_ip: bool) -> str:
    if severity == "High" and confidence == "High" and public_ip:
        return "Urgent"
    if severity == "High":
        return "High"
    if severity == "Medium" and confidence in {"High", "Medium"}:
        return "Medium"
    return "Low"


def storyline_for_alert(rule_name: str, ip: str, user: str, details: str) -> str:
    story = f"{rule_name} | IP={ip}"
    if user and user != "Unknown":
        story += f" | User={user}"
    story += f" | {details[:40]}"
    return story[:95]


# =========================
# ANALYSIS
# =========================
def analyze_logs(lines: list) -> dict:
    failed_ip_counter = Counter()
    failed_user_counter = Counter()
    suspicious_ip_counter = Counter()

    ip_fail_events = defaultdict(list)
    ip_success_events = defaultdict(list)
    ip_suspicious_events = defaultdict(list)
    user_ip_counter = defaultdict(Counter)

    raw_alerts = []

    for line in lines:
        ip = extract_ip(line)
        user = extract_username(line)
        timestamp = extract_timestamp(line)
        lowered = line.lower()

        if is_failed_login(line):
            failed_ip_counter[ip] += 1
            failed_user_counter[user] += 1
            ip_fail_events[ip].append({"timestamp": timestamp, "ip": ip, "username": user, "line": line})
            user_ip_counter[user][ip] += 1

        if is_successful_login(line):
            ip_success_events[ip].append({"timestamp": timestamp, "ip": ip, "username": user, "line": line})

        if is_suspicious(line):
            suspicious_ip_counter[ip] += 1
            ip_suspicious_events[ip].append({"timestamp": timestamp, "ip": ip, "username": user, "line": line})

        # Tooling / malicious execution
        if any(word in lowered for word in ["mimikatz", "certutil", "mshta", "regsvr32", "downloadstring", "powershell -enc", "encodedcommand"]):
            context = {
                "count": 1,
                "public_ip": is_public_ip(ip),
                "privileged": user.lower() in PRIVILEGED_USERS
            }
            raw_alerts.append({
                "rule": "MALICIOUS_TOOLING_ACTIVITY",
                "severity": RULE_METADATA["MALICIOUS_TOOLING_ACTIVITY"]["severity"],
                "confidence": alert_confidence("MALICIOUS_TOOLING_ACTIVITY", context),
                "priority": "",
                "ip": ip,
                "username": user,
                "timestamp": timestamp,
                "details": line,
                "tactic": RULE_METADATA["MALICIOUS_TOOLING_ACTIVITY"]["tactic"],
                "storyline": ""
            })

        # Persistence / impact
        if any(word in lowered for word in ["vssadmin", "shadow copies", "wbadmin", "ransom", "decryptor", "scheduled task", "schtasks", "run key", "startup folder"]):
            context = {
                "count": 1,
                "public_ip": is_public_ip(ip),
                "privileged": user.lower() in PRIVILEGED_USERS
            }
            raw_alerts.append({
                "rule": "PERSISTENCE_OR_IMPACT_SIGNAL",
                "severity": RULE_METADATA["PERSISTENCE_OR_IMPACT_SIGNAL"]["severity"],
                "confidence": alert_confidence("PERSISTENCE_OR_IMPACT_SIGNAL", context),
                "priority": "",
                "ip": ip,
                "username": user,
                "timestamp": timestamp,
                "details": line,
                "tactic": RULE_METADATA["PERSISTENCE_OR_IMPACT_SIGNAL"]["tactic"],
                "storyline": ""
            })

    # Correlation rules per IP
    for ip, fail_count in failed_ip_counter.items():
        if ip == "Unknown":
            continue

        distinct_users = len([u for u in {e['username'] for e in ip_fail_events[ip]} if u != "Unknown"])
        success_count = len(ip_success_events[ip])
        suspicious_count = len(ip_suspicious_events[ip])
        privileged_hits = [e for e in ip_fail_events[ip] if e["username"].lower() in PRIVILEGED_USERS]
        top_user = ip_fail_events[ip][0]["username"] if ip_fail_events[ip] else "Unknown"
        public_ip = is_public_ip(ip)

        if fail_count >= 3 and success_count > 0:
            context = {
                "count": fail_count,
                "success_count": success_count,
                "distinct_users": distinct_users,
                "public_ip": public_ip,
                "privileged": False
            }
            raw_alerts.append({
                "rule": "IDENTITY_COMPROMISE_SUSPECTED",
                "severity": RULE_METADATA["IDENTITY_COMPROMISE_SUSPECTED"]["severity"],
                "confidence": alert_confidence("IDENTITY_COMPROMISE_SUSPECTED", context),
                "priority": "",
                "ip": ip,
                "username": top_user,
                "timestamp": ip_success_events[ip][0]["timestamp"] if ip_success_events[ip] else "Unknown",
                "details": f"{fail_count} failures followed by {success_count} success event(s)",
                "tactic": RULE_METADATA["IDENTITY_COMPROMISE_SUSPECTED"]["tactic"],
                "storyline": ""
            })

        if distinct_users >= 5 and fail_count >= 5:
            context = {
                "count": fail_count,
                "success_count": success_count,
                "distinct_users": distinct_users,
                "public_ip": public_ip,
                "privileged": False
            }
            raw_alerts.append({
                "rule": "PASSWORD_SPRAY_SEQUENCE",
                "severity": RULE_METADATA["PASSWORD_SPRAY_SEQUENCE"]["severity"],
                "confidence": alert_confidence("PASSWORD_SPRAY_SEQUENCE", context),
                "priority": "",
                "ip": ip,
                "username": "Multiple",
                "timestamp": ip_fail_events[ip][0]["timestamp"],
                "details": f"Targeted {distinct_users} usernames with repeated failures",
                "tactic": RULE_METADATA["PASSWORD_SPRAY_SEQUENCE"]["tactic"],
                "storyline": ""
            })

        if privileged_hits and (fail_count >= 3 or suspicious_count > 0):
            context = {
                "count": fail_count,
                "success_count": success_count,
                "distinct_users": distinct_users,
                "public_ip": public_ip,
                "privileged": True
            }
            raw_alerts.append({
                "rule": "PRIVILEGED_ACCESS_ATTACK",
                "severity": RULE_METADATA["PRIVILEGED_ACCESS_ATTACK"]["severity"],
                "confidence": alert_confidence("PRIVILEGED_ACCESS_ATTACK", context),
                "priority": "",
                "ip": ip,
                "username": privileged_hits[0]["username"],
                "timestamp": privileged_hits[0]["timestamp"],
                "details": f"Privileged account targeting from {ip}",
                "tactic": RULE_METADATA["PRIVILEGED_ACCESS_ATTACK"]["tactic"],
                "storyline": ""
            })

        if fail_count >= 10:
            context = {
                "count": fail_count,
                "success_count": success_count,
                "distinct_users": distinct_users,
                "public_ip": public_ip,
                "privileged": False
            }
            raw_alerts.append({
                "rule": "AUTH_FAILURE_SPIKE",
                "severity": RULE_METADATA["AUTH_FAILURE_SPIKE"]["severity"],
                "confidence": alert_confidence("AUTH_FAILURE_SPIKE", context),
                "priority": "",
                "ip": ip,
                "username": "Multiple",
                "timestamp": ip_fail_events[ip][0]["timestamp"],
                "details": f"{fail_count} authentication failures from same source",
                "tactic": RULE_METADATA["AUTH_FAILURE_SPIKE"]["tactic"],
                "storyline": ""
            })

        if fail_count >= 5 and suspicious_count >= 2:
            context = {
                "count": fail_count + suspicious_count,
                "success_count": success_count,
                "distinct_users": distinct_users,
                "public_ip": public_ip,
                "privileged": False
            }
            raw_alerts.append({
                "rule": "SUSPICIOUS_SOURCE_AGGREGATION",
                "severity": RULE_METADATA["SUSPICIOUS_SOURCE_AGGREGATION"]["severity"],
                "confidence": alert_confidence("SUSPICIOUS_SOURCE_AGGREGATION", context),
                "priority": "",
                "ip": ip,
                "username": "Multiple",
                "timestamp": ip_fail_events[ip][0]["timestamp"],
                "details": f"Source produced repeated auth failures and suspicious activity",
                "tactic": RULE_METADATA["SUSPICIOUS_SOURCE_AGGREGATION"]["tactic"],
                "storyline": ""
            })

    # Cross-rule aggregation by public IP
    ip_rule_counter = defaultdict(set)
    for alert in raw_alerts:
        if alert["ip"] != "Unknown":
            ip_rule_counter[alert["ip"]].add(alert["rule"])

    for ip, rules in ip_rule_counter.items():
        if is_public_ip(ip) and len(rules) >= 2:
            raw_alerts.append({
                "rule": "EXTERNAL_MULTI_ALERT_SOURCE",
                "severity": RULE_METADATA["EXTERNAL_MULTI_ALERT_SOURCE"]["severity"],
                "confidence": "High" if len(rules) >= 3 else "Medium",
                "priority": "",
                "ip": ip,
                "username": "Multiple",
                "timestamp": "Correlated",
                "details": f"External source triggered {len(rules)} independent rule types",
                "tactic": RULE_METADATA["EXTERNAL_MULTI_ALERT_SOURCE"]["tactic"],
                "storyline": ""
            })

    # Dedup / suppression
    deduped_alerts = []
    seen = set()
    for alert in raw_alerts:
        key = (alert["rule"], alert["ip"], alert["username"], alert["details"])
        if key in seen:
            continue
        seen.add(key)

        public_ip = is_public_ip(alert["ip"])
        alert["priority"] = alert_priority(alert["severity"], alert["confidence"], public_ip)
        alert["storyline"] = storyline_for_alert(alert["rule"], alert["ip"], alert["username"], alert["details"])
        deduped_alerts.append(alert)

    deduped_alerts.sort(
        key=lambda a: (
            {"Urgent": 4, "High": 3, "Medium": 2, "Low": 1}.get(a["priority"], 0),
            {"High": 3, "Medium": 2, "Low": 1}.get(a["severity"], 0)
        ),
        reverse=True
    )

    severity_counter = Counter(alert["severity"] for alert in deduped_alerts)
    priority_counter = Counter(alert["priority"] for alert in deduped_alerts)
    rule_counter = Counter(alert["rule"] for alert in deduped_alerts)
    tactic_counter = Counter(alert["tactic"] for alert in deduped_alerts)
    country_counter = Counter()

    for alert in deduped_alerts:
        if is_public_ip(alert["ip"]):
            geo = get_geoip(alert["ip"])
            country_counter[geo["country"]] += 1

    return {
        "total_lines": len(lines),
        "alert_count": len(deduped_alerts),
        "alerts": deduped_alerts,
        "severity_counter": severity_counter,
        "priority_counter": priority_counter,
        "rule_counter": rule_counter,
        "tactic_counter": tactic_counter,
        "country_counter": country_counter,
        "failed_ip_counter": failed_ip_counter,
        "failed_user_counter": failed_user_counter,
        "suspicious_ip_counter": suspicious_ip_counter,
    }


# =========================
# RENDERING
# =========================
def render_summary(result: dict):
    print("\n" + Colors.CYAN + Colors.BOLD + "Mini SIEM Summary:" + Colors.RESET)

    border = "+------------------------------------------------------+"
    print(Colors.CYAN + border + Colors.RESET)
    print(Colors.WHITE + f"|{'Checking':^38}|{'Status':^15}|" + Colors.RESET)
    print(Colors.CYAN + border + Colors.RESET)

    rows = [
        ("Total Log Lines", str(result["total_lines"]), Colors.WHITE),
        ("Total Alerts", str(result["alert_count"]), Colors.RED if result["alert_count"] > 0 else Colors.GREEN),
        ("Urgent Alerts", str(result["priority_counter"].get("Urgent", 0)), Colors.RED),
        ("High Severity Alerts", str(result["severity_counter"].get("High", 0)), Colors.RED),
        ("Medium Severity Alerts", str(result["severity_counter"].get("Medium", 0)), Colors.YELLOW),
        ("Low Severity Alerts", str(result["severity_counter"].get("Low", 0)), Colors.GREEN),
    ]

    for label, value, color in rows:
        print(
            Colors.WHITE + "|" +
            f"{label:<38}" +
            "|" +
            color + f"{value:^15}" +
            Colors.WHITE + "|" +
            Colors.RESET
        )
    print(Colors.CYAN + border + Colors.RESET)


def render_distribution_table(title: str, counter: Counter):
    print("\n" + Colors.MAGENTA + Colors.BOLD + title + ":" + Colors.RESET)
    border = "+------------------------------------------------------+"
    print(Colors.CYAN + border + Colors.RESET)
    print(Colors.WHITE + f"|{'Value':^38}|{'Count':^15}|" + Colors.RESET)
    print(Colors.CYAN + border + Colors.RESET)

    items = counter.most_common()
    if not items:
        print(Colors.WHITE + f"|{'None':^38}|{'0':^15}|" + Colors.RESET)
    else:
        for label, count in items:
            color = Colors.YELLOW
            if title == "Severity Distribution":
                color = Colors.GREEN
                if label == "High":
                    color = Colors.RED
                elif label == "Medium":
                    color = Colors.YELLOW
            elif title == "Priority Distribution":
                color = Colors.GREEN
                if label == "Urgent":
                    color = Colors.RED
                elif label == "High":
                    color = Colors.MAGENTA
                elif label == "Medium":
                    color = Colors.YELLOW

            print(
                Colors.WHITE + "|" +
                f"{str(label)[:38]:<38}" +
                "|" +
                color + f"{str(count):^15}" +
                Colors.WHITE + "|" +
                Colors.RESET
            )
    print(Colors.CYAN + border + Colors.RESET)


def render_counter_table(title: str, counter: Counter, color: str, limit: int = 10):
    print("\n" + color + Colors.BOLD + title + ":" + Colors.RESET)
    border = "+------------------------------------------------------+"
    print(Colors.CYAN + border + Colors.RESET)
    print(Colors.WHITE + f"|{'Value':^38}|{'Count':^15}|" + Colors.RESET)
    print(Colors.CYAN + border + Colors.RESET)

    items = counter.most_common(limit)
    if not items:
        print(Colors.WHITE + f"|{'None':^38}|{'0':^15}|" + Colors.RESET)
    else:
        for value, count in items:
            display = str(value)[:38]
            print(
                Colors.WHITE + "|" +
                color + f"{display:<38}" +
                Colors.WHITE + "|" +
                color + f"{str(count):^15}" +
                Colors.WHITE + "|" +
                Colors.RESET
            )
    print(Colors.CYAN + border + Colors.RESET)


def render_alert_table(alerts: list, title: str, limit: int = 12):
    print("\n" + Colors.CYAN + Colors.BOLD + title + ":" + Colors.RESET)

    border = "+-------------------------------------------------------------------------------------------------------------------------------------------------------------------+"
    print(Colors.CYAN + border + Colors.RESET)
    print(Colors.WHITE + f"|{'#':^4}|{'Priority':^10}|{'Severity':^10}|{'Rule':^35}|{'IP':^18}|{'User':^14}|{'Tactic':^25}|{'Storyline':^40}|" + Colors.RESET)
    print(Colors.CYAN + border + Colors.RESET)

    if not alerts:
        print(Colors.WHITE + f"|{'-':^4}|{'-':^10}|{'-':^10}|{'None':^35}|{'None':^18}|{'None':^14}|{'None':^25}|{'None':^40}|" + Colors.RESET)
    else:
        for idx, alert in enumerate(alerts[:limit], start=1):
            pri_color = Colors.GREEN
            if alert["priority"] == "Urgent":
                pri_color = Colors.RED
            elif alert["priority"] == "High":
                pri_color = Colors.MAGENTA
            elif alert["priority"] == "Medium":
                pri_color = Colors.YELLOW

            sev_color = Colors.GREEN
            if alert["severity"] == "High":
                sev_color = Colors.RED
            elif alert["severity"] == "Medium":
                sev_color = Colors.YELLOW

            print(
                Colors.WHITE + "|" +
                f"{idx:^4}" +
                "|" +
                pri_color + f"{alert['priority']:^10}" +
                Colors.WHITE + "|" +
                sev_color + f"{alert['severity']:^10}" +
                Colors.WHITE + "|" +
                f"{alert['rule'][:26]:<35}" +
                "|" +
                f"{alert['ip'][:16]:^18}" +
                "|" +
                f"{alert['username'][:14]:^14}" +
                "|" +
                Colors.CYAN + f"{alert['tactic'][:25]:^25}" +
                Colors.WHITE + "|" +
                Colors.YELLOW + f"{alert['storyline'][:40]:<40}" +
                Colors.WHITE + "|" +
                Colors.RESET
            )

    print(Colors.CYAN + border + Colors.RESET)


def render_geo_alert_context(alerts: list, limit: int = 8):
    print("\n" + Colors.CYAN + Colors.BOLD + "Geo Context for Public Alert Sources:" + Colors.RESET)

    border = "+---------------------------------------------------------------------------------------------------------------------------+"
    print(Colors.CYAN + border + Colors.RESET)
    print(Colors.WHITE + f"|{'#':^4}|{'IP':^18}|{'Country':^18}|{'City':^18}|{'ISP':^50}|{'Priority':^10}|" + Colors.RESET)
    print(Colors.CYAN + border + Colors.RESET)

    public_alerts = []
    seen = set()
    for alert in alerts:
        if is_public_ip(alert["ip"]) and alert["ip"] not in seen:
            seen.add(alert["ip"])
            public_alerts.append(alert)

    if not public_alerts:
        print(Colors.WHITE + f"|{'-':^4}|{'None':^18}|{'None':^18}|{'None':^18}|{'None':^50}|{'-':^10}|" + Colors.RESET)
    else:
        for idx, alert in enumerate(public_alerts[:limit], start=1):
            geo = get_geoip(alert["ip"])
            pri_color = Colors.GREEN
            if alert["priority"] == "Urgent":
                pri_color = Colors.RED
            elif alert["priority"] == "High":
                pri_color = Colors.MAGENTA
            elif alert["priority"] == "Medium":
                pri_color = Colors.YELLOW

            print(
                Colors.WHITE + "|" +
                f"{idx:^4}" +
                "|" +
                Colors.YELLOW + f"{alert['ip'][:18]:^18}" +
                Colors.WHITE + "|" +
                f"{geo['country'][:18]:^18}" +
                "|" +
                f"{geo['city'][:18]:^18}" +
                "|" +
                f"{geo['isp'][:32]:^50}" +
                "|" +
                pri_color + f"{alert['priority']:^10}" +
                Colors.WHITE + "|" +
                Colors.RESET
            )

    print(Colors.CYAN + border + Colors.RESET)


def render_recommendations(result: dict):
    print("\n" + Colors.CYAN + Colors.BOLD + "Recommendations:" + Colors.RESET)
    border = "+------------------------------------------------------------------------+"
    print(Colors.CYAN + border + Colors.RESET)
    print(Colors.WHITE + f"|{'#':^6}|{'Recommendation':^65}|" + Colors.RESET)
    print(Colors.CYAN + border + Colors.RESET)

    recommendations = []

    if result["priority_counter"].get("Urgent", 0) > 0:
        recommendations.append("Investigate urgent correlated alerts first.")
        recommendations.append("Contain public sources tied to multiple alert types.")
        recommendations.append("Review identity-compromise and privilege alerts immediately.")
    elif result["priority_counter"].get("High", 0) > 0:
        recommendations.append("Review high-priority correlated alerts.")
        recommendations.append("Tune monitoring around repeated suspicious sources.")
    else:
        recommendations.append("No critical correlated alert clusters detected.")

    if result["rule_counter"].get("PASSWORD_SPRAY_SEQUENCE", 0) > 0:
        recommendations.append("Review accounts targeted in password spray behavior.")
    if result["rule_counter"].get("MALICIOUS_TOOLING_ACTIVITY", 0) > 0:
        recommendations.append("Inspect endpoints for attacker tooling execution.")
    if result["rule_counter"].get("PERSISTENCE_OR_IMPACT_SIGNAL", 0) > 0:
        recommendations.append("Check persistence and ransomware-related activity immediately.")

    deduped = []
    for item in recommendations:
        if item not in deduped:
            deduped.append(item)

    for idx, item in enumerate(deduped[:8], start=1):
        print(
            Colors.WHITE + "|" +
            f"{str(idx):^6}" +
            "|" +
            Colors.YELLOW + f"{item[:65]:<65}" +
            Colors.WHITE + "|" +
            Colors.RESET
        )
    print(Colors.CYAN + border + Colors.RESET)


# =========================
# MAIN
# =========================
def main():
    print_banner()

    print_message(Colors.BLUE + "[i] Mode        : Mini SIEM Correlation")
    print_message(Colors.BLUE + "[i] Input Type  : Text-Based Log File")
    print_message(Colors.BLUE + "[i] Detection   : Correlated Alerts + Priority + Storylining")
    print_message(Colors.BLUE + "[i] Features    : Dedup Suppression + Geo Context + ATT&CK-style Tactics\n")

    try:
        file_path = ask_input("Enter Log File Path: ").strip()

        if not file_path:
            print_message(Colors.RED + "[!] No file path provided.")
            sys.exit(1)

        print()
        print_message(Colors.YELLOW + "[-] Loading Log File ...")
        lines = load_log_file(file_path)

        print_message(Colors.YELLOW + "[-] Applying Correlation Rules ...")
        print_message(Colors.YELLOW + "[-] Building Alert Storylines and Priorities ...\n")

        result = analyze_logs(lines)

        render_summary(result)
        render_distribution_table("Severity Distribution", result["severity_counter"])
        render_distribution_table("Priority Distribution", result["priority_counter"])
        render_counter_table("Detection Rule Hits", result["rule_counter"], Colors.YELLOW)
        render_counter_table("ATT&CK-style Tactic Distribution", result["tactic_counter"], Colors.CYAN)
        render_counter_table("Country Distribution", result["country_counter"], Colors.MAGENTA)
        render_counter_table("Top Failed Source IPs", result["failed_ip_counter"], Colors.RED)
        render_counter_table("Top Targeted Usernames", result["failed_user_counter"], Colors.GREEN)
        render_counter_table("Top Suspicious IPs", result["suspicious_ip_counter"], Colors.YELLOW)
        render_alert_table(result["alerts"], "Top Correlated Alerts", limit=12)
        render_geo_alert_context(result["alerts"])
        render_recommendations(result)

    except KeyboardInterrupt:
        print_message("\n" + Colors.RED + "[!] Detection interrupted by user.")
        sys.exit(0)
    except Exception as exc:
        print_message(Colors.RED + f"[!] Unexpected error: {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()
    time.sleep(60)
    