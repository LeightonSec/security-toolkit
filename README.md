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