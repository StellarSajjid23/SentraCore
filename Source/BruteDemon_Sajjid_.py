#!/usr/bin/env python3

import re
import time
import sys
from collections import Counter, defaultdict

try:
    from colorama import init as colorama_init
    colorama_init()
except ImportError:
    pass


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


FAILED_PATTERNS = [
    r"failed password",
    r"authentication failed",
    r"login failed",
    r"invalid user",
    r"failed login",
    r"access denied",
    r"denied",
]

SUCCESS_PATTERNS = [
    r"accepted password",
    r"login successful",
    r"session opened",
    r"successfully logged in",
]

USERNAME_PATTERNS = [
    r"for invalid user ([a-zA-Z0-9._-]+)",
    r"for user ([a-zA-Z0-9._-]+)",
    r"for ([a-zA-Z0-9._-]+) from",
    r"user[:= ]+([a-zA-Z0-9._-]+)",
    r"account[:= ]+([a-zA-Z0-9._-]+)",
    r"username[:= ]+([a-zA-Z0-9._-]+)",
]

TIMESTAMP_PATTERNS = [
    r"\b(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\b",
    r"\b(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\b",
    r"\b([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\b",
]

PRIVILEGED_USERS = {"root", "admin", "administrator", "dbadmin", "sapadm", "oracle", "backupadmin"}


def print_message(message: str):
    print(message + Colors.RESET)


def ask_input(prompt: str) -> str:
    return input(Colors.YELLOW + prompt + Colors.RESET)


def print_banner():
    banner = r"""
        +--------------------------------------------------------------------+
        |    ____             _         _____                                |
        |   |  _ \           | |       |  __ \                               |
        |   | |_) |_ __ _   _| |_ ___  | |  | | ___ _ __ ___   ___  _ __     |
        |   |  _ <| '__| | | | __/ _ \ | |  | |/ _ \ '_ ` _ \ / _ \| '_ \    |
        |   | |_) | |  | |_| | ||  __/ | |__| |  __/ | | | | | (_) | | | |   |
        |   |____/|_|   \__,_|\__\___| |_____/ \___|_| |_| |_|\___/|_| |_|   |
        |                                                                    |
        |                   Brute Force Detection Tool                       |
        +--------------------------------------------------------------------+
"""
    print(Colors.RED + banner + Colors.RESET)
    print(Colors.CYAN + "[*] Internship Portfolio Edition" + Colors.RESET)
    print(Colors.GREEN + "[*] Author: Sajjid" + Colors.RESET)
    print(Colors.YELLOW + "[*] Engine: Brute Force Detection and Triage" + Colors.RESET)
    print("                                                  ")


def load_log_file(file_path: str) -> list:
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as file:
            return [line.strip() for line in file if line.strip()]
    except Exception as exc:
        print_message(Colors.RED + f"[!] Failed to Read File: {exc}")
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
    for pattern in TIMESTAMP_PATTERNS:
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


def classify_severity(attempts: int, attack_type: str = "Brute Force") -> str:
    if attack_type == "Credential Stuffing":
        return "High" if attempts >= 6 else "Medium"
    if attack_type == "Password Spray":
        return "High" if attempts >= 10 else "Medium"
    if attack_type == "Privileged Targeting":
        return "High" if attempts >= 5 else "Medium"
    if attempts >= 20:
        return "High"
    if attempts >= 8:
        return "Medium"
    return "Low"


def analyze_log(lines: list) -> dict:
    failed_events = []
    success_events = []
    failed_ip_counter = Counter()
    failed_user_counter = Counter()
    success_ip_counter = Counter()
    ip_to_user_counter = defaultdict(Counter)
    user_to_ip_counter = defaultdict(Counter)
    ip_to_failed_events = defaultdict(list)
    success_after_fail = []
    attack_findings = []

    for line in lines:
        if is_failed_login(line):
            ip = extract_ip(line)
            user = extract_username(line)
            ts = extract_timestamp(line)
            event = {"timestamp": ts, "ip": ip, "username": user, "line": line}
            failed_events.append(event)
            failed_ip_counter[ip] += 1
            failed_user_counter[user] += 1
            ip_to_user_counter[ip][user] += 1
            user_to_ip_counter[user][ip] += 1
            ip_to_failed_events[ip].append(event)

        elif is_successful_login(line):
            ip = extract_ip(line)
            user = extract_username(line)
            ts = extract_timestamp(line)
            event = {"timestamp": ts, "ip": ip, "username": user, "line": line}
            success_events.append(event)
            success_ip_counter[ip] += 1

    for event in success_events:
        if event["ip"] in failed_ip_counter and failed_ip_counter[event["ip"]] >= 3 and event["ip"] != "Unknown":
            success_after_fail.append(event)

    for ip, count in failed_ip_counter.items():
        if ip == "Unknown":
            continue
        distinct_users = len([u for u in ip_to_user_counter[ip] if u != "Unknown"])
        top_user = "Unknown"
        if ip_to_user_counter[ip]:
            top_user = ip_to_user_counter[ip].most_common(1)[0][0]

        if distinct_users >= 5 and count >= 5:
            attack_type = "Password Spray"
        elif distinct_users >= 3 and success_ip_counter.get(ip, 0) > 0:
            attack_type = "Credential Stuffing"
        elif top_user.lower() in PRIVILEGED_USERS and count >= 3:
            attack_type = "Privileged Targeting"
        elif count >= 5:
            attack_type = "Brute Force"
        else:
            continue

        attack_findings.append({
            "ip": ip,
            "attempts": count,
            "top_user": top_user,
            "severity": classify_severity(count, attack_type),
            "attack_type": attack_type
        })

    for user, ip_counts in user_to_ip_counter.items():
        if user.lower() in PRIVILEGED_USERS and sum(ip_counts.values()) >= 3:
            attack_findings.append({
                "ip": "Multiple",
                "attempts": sum(ip_counts.values()),
                "top_user": user,
                "severity": classify_severity(sum(ip_counts.values()), "Privileged Targeting"),
                "attack_type": "Privileged Targeting"
            })

    deduped = []
    seen = set()
    for item in sorted(attack_findings, key=lambda x: x["attempts"], reverse=True):
        key = (item["ip"], item["top_user"], item["attack_type"])
        if key not in seen:
            seen.add(key)
            deduped.append(item)

    severity_counter = Counter(item["severity"] for item in deduped)
    attack_type_counter = Counter(item["attack_type"] for item in deduped)

    return {
        "total_lines": len(lines),
        "failed_count": len(failed_events),
        "success_count": len(success_events),
        "unique_failed_ips": len([ip for ip in failed_ip_counter if ip != "Unknown"]),
        "unique_targeted_users": len([u for u in failed_user_counter if u != "Unknown"]),
        "failed_ip_counter": failed_ip_counter,
        "failed_user_counter": failed_user_counter,
        "brute_force_sources": deduped,
        "success_after_fail": success_after_fail,
        "failed_events": failed_events,
        "success_events": success_events,
        "severity_counter": severity_counter,
        "attack_type_counter": attack_type_counter,
    }


def render_summary(result: dict):
    print("\n" + Colors.CYAN + Colors.BOLD + "Brute Force Detection Summary:" + Colors.RESET)

    border = "+------------------------------------------------------+"
    print(Colors.CYAN + border + Colors.RESET)
    print(Colors.WHITE + f"|{'Checking':^38}|{'Status':^15}|" + Colors.RESET)
    print(Colors.CYAN + border + Colors.RESET)

    rows = [
        ("Total Log Lines", str(result["total_lines"]), Colors.WHITE),
        ("Failed Login Events", str(result["failed_count"]), Colors.RED),
        ("Successful Login Events", str(result["success_count"]), Colors.GREEN),
        ("Unique Failed Source IPs", str(result["unique_failed_ips"]), Colors.YELLOW),
        ("Targeted Usernames", str(result["unique_targeted_users"]), Colors.MAGENTA),
        ("Brute Force Sources", str(len(result["brute_force_sources"])), Colors.RED),
        ("Success After Failure", str(len(result["success_after_fail"])), Colors.YELLOW),
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


def render_severity_table(severity_counter: Counter):
    print("\n" + Colors.MAGENTA + Colors.BOLD + "Severity Distribution:" + Colors.RESET)

    border = "+------------------------------------------------------+"
    print(Colors.CYAN + border + Colors.RESET)
    print(Colors.WHITE + f"|{'Severity':^38}|{'Count':^15}|" + Colors.RESET)
    print(Colors.CYAN + border + Colors.RESET)

    rows = [
        ("High", str(severity_counter.get("High", 0)), Colors.RED),
        ("Medium", str(severity_counter.get("Medium", 0)), Colors.YELLOW),
        ("Low", str(severity_counter.get("Low", 0)), Colors.GREEN),
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


def render_source_table(sources: list, limit: int = 15):
    print("\n" + Colors.RED + Colors.BOLD + "Top Brute Force Sources:" + Colors.RESET)

    border = "+-------------------------------------------------------------------------------------------------+"
    print(Colors.CYAN + border + Colors.RESET)
    print(Colors.WHITE + f"|{'#':^5}|{'Source IP':^18}|{'Attempts':^12}|{'Top User':^20}|{'Severity':^15}|{'Type':^22}|" + Colors.RESET)
    print(Colors.CYAN + border + Colors.RESET)

    if not sources:
        print(Colors.WHITE + f"|{'-':^5}|{'None':^18}|{'0':^12}|{'None':^20}|{'-':^15}|{'-':^22}|" + Colors.RESET)
    else:
        for idx, item in enumerate(sources[:limit], start=1):
            sev_color = Colors.GREEN
            if item["severity"] == "High":
                sev_color = Colors.RED
            elif item["severity"] == "Medium":
                sev_color = Colors.YELLOW

            print(
                Colors.WHITE + "|" +
                f"{idx:^5}" +
                "|" +
                f"{item['ip'][:18]:^18}" +
                "|" +
                Colors.RED + f"{str(item['attempts']):^12}" +
                Colors.WHITE + "|" +
                f"{item['top_user'][:20]:^20}" +
                "|" +
                sev_color + f"{item['severity']:^15}" +
                Colors.WHITE + "|" +
                Colors.CYAN + f"{item['attack_type'][:22]:^22}" +
                Colors.WHITE + "|" +
                Colors.RESET
            )

    print(Colors.CYAN + border + Colors.RESET)


def render_counter_table(title: str, counter: Counter, color: str, value_label: str = "Count", limit: int = 15):
    print("\n" + color + Colors.BOLD + title + ":" + Colors.RESET)

    border = "+------------------------------------------------------+"
    print(Colors.CYAN + border + Colors.RESET)
    print(Colors.WHITE + f"|{'Value':^38}|{value_label:^15}|" + Colors.RESET)
    print(Colors.CYAN + border + Colors.RESET)

    items = counter.most_common(limit)

    if not items:
        print(Colors.WHITE + f"|{'None':^38}|{'0':^15}|" + Colors.RESET)
    else:
        for value, count in items:
            value_text = str(value)[:38]
            print(
                Colors.WHITE + "|" +
                color + f"{value_text:<38}" +
                Colors.WHITE + "|" +
                color + f"{str(count):^15}" +
                Colors.WHITE + "|" +
                Colors.RESET
            )

    print(Colors.CYAN + border + Colors.RESET)


def render_event_table(title: str, events: list, color: str, limit: int = 10):
    print("\n" + color + Colors.BOLD + title + ":" + Colors.RESET)

    border = "+------------------------------------------------------------------------------------------------------------------------------------+"
    print(Colors.CYAN + border + Colors.RESET)
    print(Colors.WHITE + f"|{'#':^5}|{'IP':^16}|{'User':^16}|{'Timestamp':^21}|{'Event':^70}|" + Colors.RESET)
    print(Colors.CYAN + border + Colors.RESET)

    if not events:
        print(Colors.WHITE + f"|{'-':^5}|{'None':^16}|{'None':^16}|{'None':^21}|{'None':^70}|" + Colors.RESET)
    else:
        for idx, event in enumerate(events[:limit], start=1):
            event_text = event["line"][:70]
            print(
                Colors.WHITE + "|" +
                f"{idx:^5}" +
                "|" +
                color + f"{event['ip'][:16]:^16}" +
                Colors.WHITE + "|" +
                f"{event['username'][:16]:^16}" +
                "|" +
                f"{event['timestamp'][:21]:^21}" +
                "|" +
                f"{event_text:<70}" +
                "|" +
                Colors.RESET
            )

    print(Colors.CYAN + border + Colors.RESET)


def render_recommendations(result: dict):
    print("\n" + Colors.CYAN + Colors.BOLD + "Recommendations:" + Colors.RESET)

    border = "+-----------------------------------------------------+"
    print(Colors.CYAN + border + Colors.RESET)
    print(Colors.WHITE + f"|{'#':^6}|{'Recommendation':^46}|" + Colors.RESET)
    print(Colors.CYAN + border + Colors.RESET)

    recommendations = []
    high_count = result["severity_counter"].get("High", 0)
    medium_count = result["severity_counter"].get("Medium", 0)
    spray_count = result["attack_type_counter"].get("Password Spray", 0)
    stuffing_count = result["attack_type_counter"].get("Credential Stuffing", 0)

    if high_count > 0:
        recommendations.append("Block or rate-limit high-risk IPs.")
        recommendations.append("Review successful logins after failures.")
        recommendations.append("Check if targeted accounts were compromised.")
    elif medium_count > 0:
        recommendations.append("Monitor repeated failed IPs closely.")
        recommendations.append("Review password policy and MFA coverage.")
    else:
        recommendations.append("No major brute-force pattern detected.")
        recommendations.append("Continue routine monitoring.")

    if spray_count > 0:
        recommendations.append("Review for password spraying behavior.")
    if stuffing_count > 0:
        recommendations.append("Check for reused credential abuse.")
    if result["unique_targeted_users"] > 0:
        recommendations.append("Review high-value usernames being targeted.")

    for idx, item in enumerate(recommendations[:6], start=1):
        text = item[:45]
        print(
            Colors.WHITE + "|" +
            f"{str(idx):^6}" +
            "|" +
            Colors.YELLOW + f"{text:<46}" +
            Colors.WHITE + "|" +
            Colors.RESET
        )

    print(Colors.CYAN + border + Colors.RESET)


def main():
    print_banner()

    print_message(Colors.BLUE + "[i] Mode        : Brute Force Detection")
    print_message(Colors.BLUE + "[i] Input Type  : Text-Based Authentication Log")
    print_message(Colors.BLUE + "[i] Detection   : Failed Login Clustering / Source Triage\n")

    try:
        file_path = ask_input("Enter Log File Path: ").strip()

        if not file_path:
            print_message(Colors.RED + "[!] No File Path Provided.")
            sys.exit(1)

        print()
        print_message(Colors.YELLOW + "[-] Loading Log File ...")
        lines = load_log_file(file_path)

        print_message(Colors.YELLOW + "[-] Detecting Brute Force Patterns...\n")
        result = analyze_log(lines)

        render_summary(result)
        render_severity_table(result["severity_counter"])
        render_source_table(result["brute_force_sources"])
        render_counter_table("Most Targeted Usernames", result["failed_user_counter"], Colors.MAGENTA)
        render_counter_table("Top Failed Source IPs", result["failed_ip_counter"], Colors.RED)
        render_counter_table("Attack Type Distribution", result["attack_type_counter"], Colors.CYAN)
        render_event_table("Sample Failed Login Events", result["failed_events"], Colors.RED)
        render_event_table("Successful Logins After Failures", result["success_after_fail"], Colors.YELLOW)
        render_recommendations(result)

    except KeyboardInterrupt:
        print_message("\n" + Colors.RED + "[!] Detection Interrupted by User.")
        sys.exit(0)
    except Exception as exc:
        print_message(Colors.RED + f"[!] Unexpected Error: {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()
    time.sleep(60)
