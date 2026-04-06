# Log Analyser
# Parses web access logs and flags suspicious activity
# Author: LeightonSec

import sys
from collections import Counter

def load_log(filepath):
    try:
        with open(filepath, 'r') as f:
            lines = f.readlines()
        print(f"Loaded {len(lines)} log entries from {filepath}\n")
        return lines
    except FileNotFoundError:
        print(f"Error: File not found — {filepath}")
        sys.exit(1)

def count_ips(lines):
    ips = [line.split()[0] for line in lines]
    return Counter(ips)

def flag_suspicious(lines, threshold=3):
    ip_404s = Counter()
    for line in lines:
        parts = line.split()
        ip = parts[0]
        status = parts[8]
        if status == "404":
            ip_404s[ip] += 1
    suspicious = {ip: count for ip, count in ip_404s.items() if count >= threshold}
    return suspicious

def main():
    print("Log Analyser — Starting...")
    lines = load_log("access.log")

    ip_counts = count_ips(lines)
    print("--- Top IPs by Request Count ---")
    for ip, count in ip_counts.most_common(10):
        print(f"  {ip} — {count} requests")

    print("\n--- Suspicious IPs (3+ 404 errors) ---")
    suspicious = flag_suspicious(lines)
    if suspicious:
        for ip, count in suspicious.items():
            print(f"  ⚠️  {ip} — {count} 404 errors — INVESTIGATE")
    else:
        print("  No suspicious activity detected.")

main()