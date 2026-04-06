# Log Analyser

A Python script that parses web access logs and flags suspicious activity.

## What it does
- Loads and parses web server access logs
- Counts requests per IP address
- Flags IPs with 3+ 404 errors as suspicious

## Why I built this
Built to reinforce log analysis skills learned through Splunk SIEM training. 
Mirrors real SOC analyst workflows — parse, count, flag, investigate.

## Usage
```bash
python log_analyser.py
```

## Sample Output

--- Top IPs by Request Count ---
192.168.1.1 — 4 requests
192.168.1.2 — 4 requests
--- Suspicious IPs (3+ 404 errors) ---
⚠️  192.168.1.2 — 4 404 errors — INVESTIGATE
⚠️  192.168.1.1 — 3 404 errors — INVESTIGATE

## Author
LeightonSec — IT & Cybersecurity | CompTIA Security+ | Splunk