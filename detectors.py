import re
import logging
from collections import Counter, defaultdict
from urllib.parse import unquote

logger = logging.getLogger(__name__)

# Known scanning and attack tool signatures
SUSPICIOUS_UA_PATTERNS = [
    r'sqlmap', r'nikto', r'nmap', r'masscan', r'zgrab',
    r'nessus', r'openvas', r'metasploit', r'burpsuite', r'hydra',
    r'dirbuster', r'gobuster', r'wfuzz', r'nuclei', r'acunetix'
]
SUSPICIOUS_UA_RE = re.compile('|'.join(SUSPICIOUS_UA_PATTERNS), re.IGNORECASE)

# Directory traversal — catches encoded variants too
TRAVERSAL_RE = re.compile(r'\.\.[/\\]|%2e%2e[%2f%5c]', re.IGNORECASE)

# SQL injection patterns in URL paths — non-greedy to avoid ReDoS
SQLI_RE = re.compile(
    r'(union\s+select|select\s+.+?\s+from|insert\s+into|drop\s+table'
    r'|or\s+1\s*=\s*1|\'or\'|--\s|/\*.+?\*/|xp_cmdshell|exec\s*\()',
    re.IGNORECASE
)


def detect_404_scanners(entries: list, threshold: int = 3) -> dict:
    """Flag IPs with excessive 404s — likely directory or file scanning"""
    ip_404s = Counter()
    for entry in entries:
        if entry.status == 404:
            ip_404s[entry.ip] += 1
    return {ip: count for ip, count in ip_404s.items() if count >= threshold}


def detect_high_volume(entries: list, threshold: int = 100) -> dict:
    """Flag IPs with abnormally high request counts — brute force or DDoS indicator"""
    ip_counts = Counter(entry.ip for entry in entries)
    return {ip: count for ip, count in ip_counts.items() if count >= threshold}


def detect_suspicious_agents(entries: list) -> dict:
    """Flag requests from known attack and scanning tools"""
    flagged = defaultdict(set)
    for entry in entries:
        if SUSPICIOUS_UA_RE.search(entry.user_agent):
            flagged[entry.ip].add(entry.user_agent)
    return {ip: list(agents) for ip, agents in flagged.items()}


def detect_traversal(entries: list) -> dict:
    """Flag directory traversal attempts — checks raw and URL-decoded paths"""
    flagged = defaultdict(int)
    for entry in entries:
        decoded = unquote(entry.path)
        if TRAVERSAL_RE.search(entry.path) or TRAVERSAL_RE.search(decoded):
            flagged[entry.ip] += 1
    return dict(flagged)


def detect_sqli(entries: list) -> dict:
    """Flag SQL injection patterns — checks raw and URL-decoded paths"""
    flagged = defaultdict(int)
    for entry in entries:
        decoded = unquote(entry.path)
        if SQLI_RE.search(entry.path) or SQLI_RE.search(decoded):
            flagged[entry.ip] += 1
    return dict(flagged)


def run_all(entries: list, thresholds: dict = None) -> dict:
    """Run all detectors and return combined findings"""
    t = thresholds or {}
    findings = {
        "404_scanning": detect_404_scanners(entries, t.get("404", 3)),
        "high_volume": detect_high_volume(entries, t.get("volume", 100)),
        "suspicious_agents": detect_suspicious_agents(entries),
        "traversal": detect_traversal(entries),
        "sqli": detect_sqli(entries),
    }
    total = sum(len(v) for v in findings.values())
    logger.info(f"Detection complete — {total} threat(s) identified across {len(findings)} categories")
    return findings
