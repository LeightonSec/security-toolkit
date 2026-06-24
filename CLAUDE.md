# CLAUDE.md — Security Toolkit

## What This Is
A growing collection of security scripts and utilities built while
transitioning into cybersecurity. Currently contains the Log Analyser, a
modular Python tool that parses web server access logs and detects threats
across several categories. Built as part of the LeightonSec SOC Toolkit.

## SOC Toolkit Position
- **Layer:** Detection
- **Receives from:** Web server log files
- **Feeds into:** Future Incident Tracker (response layer), future Unified Dashboard
- **Gap it fills:** Log-based threat detection and suspicious activity flagging

## Architecture
Modular pipeline orchestrated by `analyser.py` (CLI entry point):
- `analyser.py` — Orchestrator: argument parsing, path validation, wiring
- `log_parser.py` — Parses Combined and Common Log Format into LogEntry objects
- `detectors.py` — All detection rules (404 scanning, high volume, suspicious
  user agents, directory traversal, SQL injection)
- `reporter.py` — Builds and saves the Markdown report
- `test_detectors.py` — Adversarial test suite for the detection pipeline
- `pre_publish.sh` — Local quality gate (secrets, README, bandit, tests, etc.)
- `README.md` — Documentation with sample output

## Current Status
✅ Complete and live — LeightonSec/security-toolkit
✅ Modular parser / detectors / reporter design
✅ Detects 404 scanning, high request volume, suspicious user agents,
   directory traversal (incl. encoded variants), and SQL injection
✅ SQLi detection hardened against string-boolean and comment-terminator
   evasion, with false-positive guards on INSERT INTO
✅ Adversarial test suite (31 tests) with locked regression cases
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
- Each tool is self-contained; larger tools use a modular file layout
- Every tool needs a solid README with sample output
- Push regularly to keep contribution graph green
- Scripts should be readable and well commented — portfolio code