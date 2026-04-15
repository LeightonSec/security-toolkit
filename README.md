# Security Toolkit — Log Analyser

A modular web server log analysis tool that parses access logs and detects threats — built to mirror real SOC analyst workflows.

---

## Skills Demonstrated

| Area | Detail |
|---|---|
| **Python** | Modular design, dataclasses, regex, argparse, file I/O |
| **Security Engineering** | Input validation, path traversal prevention, non-ReDoS regex patterns |
| **Threat Detection** | 404 scanning, brute force, directory traversal, SQLi, suspicious user agents |
| **SOC Workflows** | Log parsing, indicator flagging, structured report generation |
| **Secure Coding** | No hardcoded paths, untrusted input handling, no shell execution |

---

## What It Does

Automates the manual process of sifting through web server access logs to surface suspicious behaviour. Outputs a structured Markdown report saved to `reports/` for review.

---

## Detections

| Detection | Description |
|---|---|
| **404 Scanning** | IPs generating excessive 404 errors — directory/file enumeration |
| **High Request Volume** | Abnormal request counts — brute force or DDoS indicator |
| **Suspicious User Agents** | Known attack tools: sqlmap, nikto, nmap, gobuster, hydra and more |
| **Directory Traversal** | `../` patterns and URL-encoded variants in request paths |
| **SQL Injection** | UNION SELECT, DROP TABLE, OR 1=1 and other SQLi signatures in paths |

---

## Usage

```bash
# Analyse default access.log
python3 analyser.py

# Analyse a specific log file
python3 analyser.py /var/log/nginx/access.log

# Adjust detection thresholds
python3 analyser.py --threshold-404 5 --threshold-volume 200

# Print to stdout only, no file saved
python3 analyser.py --no-save
```

---

## Project Structure

```
security-toolkit/
├── analyser.py      # Main orchestrator — CLI entry point
├── log_parser.py    # Log parsing — Combined and Common Log Format
├── detectors.py     # Detection rules — all threat logic lives here
├── reporter.py      # Report builder — Markdown output and file saving
├── reports/         # Generated reports (gitignored)
└── LICENSE
```

---

## Sample Output

```
## 🔍 404 Scanning
- `192.168.1.2` — 4 x 404 errors
- `192.168.1.1` — 3 x 404 errors

## 🛠️ Suspicious User Agents
- `10.0.0.5` — sqlmap/1.7

## 📁 Directory Traversal Attempts
- `10.0.0.6` — 2 attempt(s)

## 💉 SQL Injection Attempts
- `10.0.0.5` — 2 attempt(s)
```

---

## Security Design

- Log file path resolved with `os.path.realpath()` — prevents path traversal on the analyser itself
- All regex patterns use non-greedy quantifiers — no ReDoS exposure
- Log content treated as untrusted input throughout — no eval, no shell execution
- Reports saved locally only — nothing sent externally

---

## Why I Built This

Built to reinforce log analysis skills from Splunk SIEM training and translate them into working code. A SOC analyst reads logs manually — this tool automates the triage layer: parse, detect, report.

---

## Author

**Leighton Wilson** — IT Deployment Engineer transitioning into Cybersecurity
CompTIA Security+ | Splunk | [LeightonSec GitHub](https://github.com/LeightonSec)

---

*Part of the LeightonSec security toolkit.*
