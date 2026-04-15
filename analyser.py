import argparse
import logging
import sys
import os

from log_parser import parse_log
from detectors import run_all
from reporter import build_report, save_report

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def validate_log_path(path: str) -> str:
    """Resolve and validate log file path — rejects traversal attempts"""
    resolved = os.path.realpath(path)
    if not os.path.isfile(resolved):
        raise argparse.ArgumentTypeError(f"File not found: {path}")
    return resolved


def main():
    parser = argparse.ArgumentParser(
        description="LeightonSec Log Analyser — detect threats in web server access logs"
    )
    parser.add_argument(
        "logfile",
        nargs="?",
        default="access.log",
        type=validate_log_path,
        help="Path to the access log file (default: access.log)"
    )
    parser.add_argument(
        "--threshold-404", type=int, default=3, metavar="N",
        help="Minimum 404 errors to flag an IP (default: 3)"
    )
    parser.add_argument(
        "--threshold-volume", type=int, default=100, metavar="N",
        help="Minimum requests to flag high volume (default: 100)"
    )
    parser.add_argument(
        "--no-save", action="store_true",
        help="Print report to stdout only, do not save to file"
    )
    args = parser.parse_args()

    thresholds = {
        "404": args.threshold_404,
        "volume": args.threshold_volume,
    }

    logger.info(f"Analysing: {args.logfile}")

    try:
        entries = parse_log(args.logfile)
    except (FileNotFoundError, PermissionError):
        sys.exit(1)

    if not entries:
        logger.warning("No valid log entries parsed. Check the log format.")
        sys.exit(1)

    findings = run_all(entries, thresholds)
    report = build_report(args.logfile, entries, findings)

    print(report)

    if not args.no_save:
        saved_path = save_report(report, args.logfile)
        print(f"Report saved to: {saved_path}")


if __name__ == "__main__":
    main()
