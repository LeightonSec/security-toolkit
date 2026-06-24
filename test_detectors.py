"""Test suite for the security-toolkit detection pipeline.

Weighted toward detectors.py, the security logic. Coverage is adversarial:
evasion variants, false-positive checks, and locked regression tests for
gaps that were found and fixed (see the *_regression tests below).

log_parser and reporter get a single smoke class each by design.
"""

import pytest

from log_parser import LogEntry, parse_line
from detectors import (
    detect_404_scanners,
    detect_high_volume,
    detect_suspicious_agents,
    detect_traversal,
    detect_sqli,
    run_all,
)
from reporter import build_report


def entry(path="/", status=200, ua="Mozilla/5.0", ip="10.0.0.1"):
    """Build a LogEntry for a single synthetic request."""
    return LogEntry(
        ip=ip,
        time="01/Jan/2024:00:00:00 +0000",
        method="GET",
        path=path,
        status=status,
        size="100",
        user_agent=ua,
    )


# ---------------------------------------------------------------------------
# SQL injection — heaviest section
# ---------------------------------------------------------------------------
class TestSqli:
    def test_union_select(self):
        e = entry(path="/login?id=1 UNION SELECT password FROM users")
        assert "10.0.0.1" in detect_sqli([e])

    def test_or_1_equals_1(self):
        e = entry(path="/login?id=1 OR 1=1")
        assert "10.0.0.1" in detect_sqli([e])

    def test_drop_table(self):
        e = entry(path="/p?q=1; DROP TABLE users")
        assert "10.0.0.1" in detect_sqli([e])

    def test_url_encoded_union_select(self):
        # %20 = space; detector decodes before matching
        e = entry(path="/login?id=1%20UNION%20SELECT%20pw%20FROM%20users")
        assert "10.0.0.1" in detect_sqli([e])

    def test_insert_into_real_still_fires(self):
        # Real INSERT with SQL context must remain detected after the FP fix.
        for path in ("/p; INSERT INTO users VALUES(1)", "/p; INSERT INTO users(name)"):
            assert "10.0.0.1" in detect_sqli([entry(path=path)]), path

    # --- Locked regression tests: gaps found and fixed in detectors.py ---

    def test_sqli_string_boolean_regression(self):
        # REGRESSION: string-based boolean tautology slipped through before the
        # quoted OR/AND pattern was added. Must stay detected.
        e = entry(path="/login?user=admin' OR 'a'='a")
        assert "10.0.0.1" in detect_sqli([e])

    def test_sqli_comment_terminator_regression(self):
        # REGRESSION: trailing comment terminator (no following whitespace) was
        # missed before the '-- / ;-- patterns were added. Must stay detected.
        e = entry(path="/login?user=admin'--")
        assert "10.0.0.1" in detect_sqli([e])

    def test_sqli_insert_fp_regression(self):
        # REGRESSION: bare "insert into" in plain English used to false-positive.
        # INSERT INTO now requires SQL context, so this must stay clean.
        e = entry(path="/search?q=insert into your cart")
        assert detect_sqli([e]) == {}

    def test_benign_paths_stay_clean(self):
        for path in (
            "/index.html",
            "/products?name=selection from catalog",
            "/articles/how-to-insert-into-a-list",
        ):
            assert detect_sqli([entry(path=path)]) == {}, path


# ---------------------------------------------------------------------------
# Directory traversal — encoding variants (proven) plus FP check
# ---------------------------------------------------------------------------
class TestTraversal:
    def test_basic(self):
        assert "10.0.0.1" in detect_traversal([entry(path="/../../etc/passwd")])

    def test_encoded_slash(self):
        assert "10.0.0.1" in detect_traversal([entry(path="/..%2f..%2fetc/passwd")])

    def test_encoded_dots(self):
        assert "10.0.0.1" in detect_traversal([entry(path="/%2e%2e/%2e%2e/etc/passwd")])

    def test_double_encoded(self):
        assert "10.0.0.1" in detect_traversal([entry(path="/%252e%252e%252fetc/passwd")])

    def test_backslash_variant(self):
        assert "10.0.0.1" in detect_traversal([entry(path="/..%5cwindows")])

    def test_benign_filename_no_fp(self):
        # ".." inside a filename (not followed by a separator) must not flag.
        assert detect_traversal([entry(path="/files/report..pdf")]) == {}


# ---------------------------------------------------------------------------
# Suspicious user agents — hits and clean misses
# ---------------------------------------------------------------------------
class TestSuspiciousAgents:
    def test_sqlmap_flagged(self):
        result = detect_suspicious_agents([entry(ua="sqlmap/1.7")])
        assert "10.0.0.1" in result
        assert "sqlmap/1.7" in result["10.0.0.1"]

    def test_multiple_tools_flagged(self):
        for ua in ("nikto/2.5", "Nmap Scripting Engine", "gobuster/3.6", "hydra"):
            assert "10.0.0.1" in detect_suspicious_agents([entry(ua=ua)]), ua

    def test_benign_agents_clean(self):
        for ua in ("Mozilla/5.0", "curl/7.0", "Googlebot/2.1"):
            assert detect_suspicious_agents([entry(ua=ua)]) == {}, ua


# ---------------------------------------------------------------------------
# Threshold detectors — boundary correctness for count-based rules
# ---------------------------------------------------------------------------
class TestThresholdDetectors:
    def test_404_at_threshold_flags(self):
        entries = [entry(status=404) for _ in range(3)]
        assert detect_404_scanners(entries, threshold=3) == {"10.0.0.1": 3}

    def test_404_below_threshold_clean(self):
        entries = [entry(status=404) for _ in range(2)]
        assert detect_404_scanners(entries, threshold=3) == {}

    def test_404_ignores_non_404_status(self):
        entries = [entry(status=200) for _ in range(10)]
        assert detect_404_scanners(entries, threshold=3) == {}

    def test_high_volume_at_threshold_flags(self):
        entries = [entry() for _ in range(5)]
        assert detect_high_volume(entries, threshold=5) == {"10.0.0.1": 5}

    def test_high_volume_below_threshold_clean(self):
        entries = [entry() for _ in range(4)]
        assert detect_high_volume(entries, threshold=5) == {}


# ---------------------------------------------------------------------------
# run_all — integration of all detectors
# ---------------------------------------------------------------------------
class TestRunAll:
    def test_returns_all_categories(self):
        findings = run_all([entry()])
        assert set(findings) == {
            "404_scanning",
            "high_volume",
            "suspicious_agents",
            "traversal",
            "sqli",
        }

    def test_flags_across_categories(self):
        entries = [
            entry(path="/x?id=1 UNION SELECT a FROM b"),
            entry(path="/../../etc/passwd", ip="10.0.0.2"),
            entry(ua="sqlmap/1.7", ip="10.0.0.3"),
        ]
        findings = run_all(entries)
        assert "10.0.0.1" in findings["sqli"]
        assert "10.0.0.2" in findings["traversal"]
        assert "10.0.0.3" in findings["suspicious_agents"]


# ---------------------------------------------------------------------------
# log_parser — smoke
# ---------------------------------------------------------------------------
class TestLogParserSmoke:
    def test_parses_combined_format(self):
        line = (
            '192.168.1.1 - - [01/Jan/2024:00:00:01 +0000] '
            '"GET /index.html HTTP/1.1" 200 512 "-" "Mozilla/5.0"'
        )
        e = parse_line(line)
        assert e is not None
        assert e.ip == "192.168.1.1"
        assert e.status == 200
        assert e.user_agent == "Mozilla/5.0"

    def test_parses_common_format_without_useragent(self):
        line = '10.0.0.1 - - [01/Jan/2024:00:00:01 +0000] "GET / HTTP/1.1" 200 512'
        e = parse_line(line)
        assert e is not None
        assert e.user_agent == "unknown"

    def test_malformed_line_returns_none(self):
        assert parse_line("this is not a log line") is None

    def test_blank_line_returns_none(self):
        assert parse_line("   ") is None


# ---------------------------------------------------------------------------
# reporter — smoke
# ---------------------------------------------------------------------------
class TestReporterSmoke:
    def test_report_contains_sections_and_counts(self):
        entries = [entry(path="/x?id=1 UNION SELECT a FROM b")]
        findings = run_all(entries)
        report = build_report("access.log", entries, findings)
        assert "Security Log Analysis Report" in report
        assert "SQL Injection Attempts" in report
        assert "Suspicious IPs identified:** 1" in report

    def test_empty_findings_render_no_threats(self):
        entries = [entry()]
        findings = run_all(entries)
        report = build_report("access.log", entries, findings)
        assert "No threats detected." in report


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
