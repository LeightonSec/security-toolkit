# CLAUDE.md — Security Toolkit

## What This Is
A growing collection of security scripts and utilities built while 
transitioning into cybersecurity. Currently contains the Log Analyser — 
a Python script that parses web server access logs and flags suspicious 
activity. Built as part of the LeightonSec SOC Toolkit.

## SOC Toolkit Position
- **Layer:** Detection
- **Receives from:** Web server log files
- **Feeds into:** Future Incident Tracker (response layer), future Unified Dashboard
- **Gap it fills:** Log-based threat detection and suspicious activity flagging

## Architecture
- `log_analyser.py` — Main script, parses access logs, flags suspicious IPs
- `README.md` — Documentation with sample output

## Current Status
✅ Complete and live — LeightonSec/security-toolkit
✅ Parses web server access logs
✅ Flags IPs with 3+ 404 errors as suspicious
✅ Counts requests per IP
✅ Clean README with sample output

## Planned Additions
- [ ] PCAP Analyser — DoS/DDoS, port scan, MitM, C2 detection (PyShark, AbuseIPDB)
- [ ] Password Policy Checker — NIST guidelines
- [ ] Port Scanner — Python based
- [ ] Post-cert: AWS IAM Audit Script, Serverless Honeypot, AWS Threat Hunter

## PCAP Analyser Design (next build)
Detection categories:
- DoS/DDoS — high volume from single IP, SYN floods, ICMP floods
- Port scanning — single IP hitting many ports rapidly
- MitM/ARP spoofing — multiple MACs claiming same IP
- C2/Malware — beaconing, DNS tunnelling, known malicious IPs (AbuseIPDB)

Stack: PyShark, AbuseIPDB API, Flask web interface, JSON reporting

## Tech Stack
- Python
- Standard library (re, collections, datetime)

## Security Rules
- No API keys in this repo currently
- Log files never committed — always gitignored
- Future tools must follow same .env pattern as ai-firewall and intel-pipeline

## Conventions
- Each tool is a standalone script
- Every tool needs a solid README with sample output
- Push regularly to keep contribution graph green
- Scripts should be readable and well commented — portfolio code