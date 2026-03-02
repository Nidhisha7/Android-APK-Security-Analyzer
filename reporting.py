#!/usr/bin/env python3


import json
from dataclasses import asdict
from typing import List

from core import Finding, SEV_ORDER


def print_table(findings: List[Finding]) -> None:
    findings = sorted(
        findings,
        key=lambda f: (-SEV_ORDER.get(f.severity, 0), f.rule_id, f.file),
    )
    headers = ("SEV", "RULE", "LOCATION", "MESSAGE")
    rows = [f.to_row() for f in findings]
    data = [headers] + rows
    widths = [max(len(str(r[i])) for r in data) for i in range(4)]

    def fmt(row):
        return "  ".join(str(row[i]).ljust(widths[i]) for i in range(4))

    print(fmt(headers))
    print("-" * (sum(widths) + 6))
    for r in rows:
        print(fmt(r))

    print()
    counts = {k: 0 for k in SEV_ORDER}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    print("Summary:")
    for k in ["HIGH", "MEDIUM", "LOW", "INFO"]:
        print(f"  {k}: {counts.get(k, 0)}")
    print(f"  Total: {len(findings)}")


def write_json(findings: List[Finding], path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump([asdict(x) for x in findings], f, indent=2, ensure_ascii=False)


def write_html(findings: List[Finding], path: str) -> None:
    """Generate an HTML report for findings."""
    html = [
        "<!DOCTYPE html>",
        "<html><head><meta charset='utf-8'><title>Report</title>",
        """
<style>
body { font-family: Arial, sans-serif; margin: 20px; }
table { border-collapse: collapse; width: 100%; }
th, td { border: 1px solid #ccc; padding: 8px; text-align: left; }
th { background-color: #f2f2f2; }
tr:nth-child(even) { background-color: #fafafa; }
.HIGH { background-color: #ffcccc; }
.MEDIUM { background-color: #fff2cc; }
.LOW { background-color: #ccffcc; }
.INFO { background-color: #e6f7ff; }
h1 { color: #333; }
</style></head><body>
""",
        "<h1>Security Report</h1>",
        "<table>",
        "<tr><th>Severity</th><th>Rule ID</th><th>Location</th><th>Message</th></tr>",
    ]

    for f in sorted(findings, key=lambda x: -SEV_ORDER.get(x.severity, 0)):
        loc = f"{f.file}:{f.line}" if f.line and f.line > 0 else f.file
        html.append(
            f"<tr class='{f.severity}'><td>{f.severity}</td>"
            f"<td>{f.rule_id}</td><td>{loc}</td><td>{f.message}</td></tr>"
        )

    html.append("</table>")

    counts = {k: 0 for k in SEV_ORDER}
    for f in findings:
        counts[f.severity] += 1

    html.append("<h2>Summary</h2><ul>")
    for k in ["HIGH", "MEDIUM", "LOW", "INFO"]:
        html.append(f"<li><b>{k}</b>: {counts.get(k, 0)}</li>")
    html.append(f"<li><b>Total</b>: {len(findings)}</li></ul>")
    html.append("</body></html>")

    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(html))
