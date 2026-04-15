import re
import logging
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)

# Combined Log Format — also handles Common Log Format (no user agent)
LOG_PATTERN = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) \S+" '
    r'(?P<status>\d{3}) (?P<size>\S+)'
    r'(?: "(?P<referer>[^"]*)" "(?P<useragent>[^"]*)")?'
)


@dataclass
class LogEntry:
    ip: str
    time: str
    method: str
    path: str
    status: int
    size: str
    user_agent: str


def parse_line(line: str) -> Optional[LogEntry]:
    """Parse a single log line — returns None if malformed"""
    line = line.strip()
    if not line:
        return None
    match = LOG_PATTERN.match(line)
    if not match:
        logger.debug(f"Could not parse line: {line[:80]}")
        return None
    return LogEntry(
        ip=match.group("ip"),
        time=match.group("time"),
        method=match.group("method"),
        path=match.group("path"),
        status=int(match.group("status")),
        size=match.group("size"),
        user_agent=match.group("useragent") or "unknown"
    )


def parse_log(filepath: str) -> list:
    """Parse entire log file — returns list of LogEntry objects"""
    entries = []
    skipped = 0
    try:
        with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
            for lineno, line in enumerate(f, 1):
                entry = parse_line(line)
                if entry:
                    entries.append(entry)
                elif line.strip():
                    skipped += 1
                    logger.debug(f"Skipped malformed line {lineno}")
    except FileNotFoundError:
        logger.error(f"Log file not found: {filepath}")
        raise
    except PermissionError:
        logger.error(f"Permission denied reading: {filepath}")
        raise

    logger.info(f"Parsed {len(entries)} valid entries ({skipped} skipped) from {filepath}")
    return entries
