#!/usr/bin/env python3

import argparse
import os
import sys

from core import analyze_apk
from reporting import print_table, write_json, write_html


def main() -> None:
    ap = argparse.ArgumentParser(
        description="mini_qark_apk — scan an APK for common Android security issues"
    )
    ap.add_argument("apk", help="Path to the APK file")
    ap.add_argument("--json", help="Write findings to JSON")
    ap.add_argument("--html", help="Write findings to HTML report")

    args = ap.parse_args()
    apk_path = args.apk

    if not os.path.exists(apk_path):
        print(f"ERROR: APK not found: {apk_path}")
        sys.exit(2)

    print(f"Scanning APK: {apk_path}")
    findings = analyze_apk(apk_path)

    if not findings:
        print("No findings ")
    else:
        print_table(findings)

    if args.json:
        write_json(findings, args.json)
        print(f"Wrote JSON report to {args.json}")
    if args.html:
        write_html(findings, args.html)
        print(f"Wrote HTML report to {args.html}")


if __name__ == "__main__":
    main()
