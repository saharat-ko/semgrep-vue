import json
import csv
import os
import glob
from datetime import datetime

RESULTS_DIR = "results"
OUTPUT_CSV = "results/summary.csv"
OUTPUT_HTML = "results/report.html"

def load_all_results():
    rows = []
    summaries = {}

    for json_file in sorted(glob.glob(f"{RESULTS_DIR}/v*.json")):
        version = os.path.basename(json_file).replace(".json", "")
        
        with open(json_file) as f:
            data = json.load(f)

        findings = data.get("results", [])
        
        summaries[version] = {
            "total": len(findings),
            "by_severity": {}
        }

        for finding in findings:
            severity = finding.get("extra", {}).get("severity", "UNKNOWN")
            summaries[version]["by_severity"][severity] = \
                summaries[version]["by_severity"].get(severity, 0) + 1

            rows.append({
                "version": version,
                "rule_id": finding.get("check_id", ""),
                "severity": severity,
                "file": finding.get("path", ""),
                "line": finding.get("start", {}).get("line", ""),
                "message": finding.get("extra", {}).get("message", "")[:200],
            })

    return rows, summaries


def save_csv(rows):
    if not rows:
        print("⚠️  No findings to export")
        return
    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)
    print(f"✅ CSV saved: {OUTPUT_CSV}")


def save_html(summaries):
    severity_colors = {
        "ERROR": "#e74c3c",
        "WARNING": "#f39c12",
        "INFO": "#3498db",
        "UNKNOWN": "#95a5a6"
    }

    rows_html = ""
    for version, data in sorted(summaries.items()):
        sev_breakdown = ", ".join(
            f'<span style="color:{severity_colors.get(s,"#333")}">{s}: {c}</span>'
            for s, c in sorted(data["by_severity"].items())
        )
        rows_html += f"""
        <tr>
            <td><strong>{version}</strong></td>
            <td>{data['total']}</td>
            <td>{sev_breakdown or '-'}</td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Semgrep Vue 3 Scan Report</title>
<style>
  body {{ font-family: sans-serif; padding: 2rem; background: #f5f5f5; }}
  h1 {{ color: #2c3e50; }}
  table {{ border-collapse: collapse; width: 100%; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }}
  th {{ background: #2c3e50; color: white; padding: 12px 16px; text-align: left; }}
  td {{ padding: 10px 16px; border-bottom: 1px solid #eee; }}
  tr:hover {{ background: #f9f9f9; }}
  .meta {{ color: #666; margin-bottom: 1rem; }}
</style>
</head>
<body>
<h1>🔍 Semgrep Vue 3 Scan Report</h1>
<p class="meta">Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
<table>
  <thead><tr><th>Version</th><th>Total Findings</th><th>By Severity</th></tr></thead>
  <tbody>{rows_html}</tbody>
</table>
</body>
</html>"""

    with open(OUTPUT_HTML, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"✅ HTML saved: {OUTPUT_HTML}")


def print_summary(summaries):
    print("\n📊 Summary per Version:")
    print(f"{'Version':<12} {'Total':>8} {'ERROR':>8} {'WARNING':>10} {'INFO':>8}")
    print("-" * 52)
    for version, data in sorted(summaries.items()):
        sev = data["by_severity"]
        print(f"{version:<12} {data['total']:>8} "
              f"{sev.get('ERROR',0):>8} "
              f"{sev.get('WARNING',0):>10} "
              f"{sev.get('INFO',0):>8}")


if __name__ == "__main__":
    rows, summaries = load_all_results()
    save_csv(rows)
    save_html(summaries)
    print_summary(summaries)