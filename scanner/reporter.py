
import json
import os
from datetime import datetime, timezone


SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

SEVERITY_COLOR = {
    "CRITICAL": "\033[91m",
    "HIGH":     "\033[31m",
    "MEDIUM":   "\033[93m",
    "LOW":      "\033[94m",
    "INFO":     "\033[37m",
}
RESET = "\033[0m"
BOLD  = "\033[1m"
DIM   = "\033[2m"
GREEN = "\033[92m"
CYAN  = "\033[96m"


def _c(severity, text):
    return f"{SEVERITY_COLOR.get(severity, '')}{text}{RESET}"


def _sorted(findings):
    return sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.get("severity", "INFO"), 99))


def _counts(findings):
    counts = {}
    for f in findings:
        s = f.get("severity", "INFO")
        counts[s] = counts.get(s, 0) + 1
    return counts


def print_findings(findings, target_url):
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    counts = _counts(findings)
    sorted_findings = _sorted(findings)

    print(f"""
{BOLD}{CYAN}╔══════════════════════════════════════════════════════════════╗
║   ██████╗ █████╗ ██████╗ ██╗     ║
║  ██╔════╝██╔══██╗██╔══██╗██║     ║
║  ██║     ███████║██████╔╝██║     ║
║  ██║     ██╔══██║██╔══██╗██║     ║
║  ╚██████╗██║  ██║██║  ██║███████╗║
║   ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚║
╠══════════════════════════════════════════════════════════════╣
║                                                              ║
║   🚀  CARLTECH  |  Supabase Security Scanner                 ║
║   🔗  github.com/carl24tech/Supabase-Scanner                 ║
║                                                              ║
║   🎯  Features: RLS Auditing | API Discovery | Auth Testing  ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝{RESET}
{BOLD}Target   :{RESET} {target_url}
{BOLD}Scan time:{RESET} {ts}
{BOLD}Findings :{RESET} {len(findings)} total
""")

    print(f"{BOLD}Summary{RESET}")
    print("  " + "─" * 36)
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        n = counts.get(sev, 0)
        bar = "█" * min(n, 20)
        label = f"  {_c(sev, sev):<30}"
        print(f"{label} {n:>3}  {DIM}{bar}{RESET}")

    print(f"\n{BOLD}Findings{RESET}\n" + "─" * 70)

    prev_sev = None
    for i, finding in enumerate(sorted_findings, 1):
        sev = finding.get("severity", "INFO")
        if sev != prev_sev:
            print(f"\n{_c(sev, f'── {sev} ' + '─' * (60 - len(sev)))}")
            prev_sev = sev

        issue = finding.get("issue", "")
        print(f"\n  {DIM}{i:>3}.{RESET} {issue}")
        for k, v in finding.items():
            if k in ("severity", "issue"):
                continue
            print(f"       {DIM}{k}:{RESET} {v}")

    print("\n" + "─" * 70)
    critical = counts.get("CRITICAL", 0)
    high = counts.get("HIGH", 0)

    if critical:
        print(_c("CRITICAL", f"\n  ⚠  {critical} CRITICAL finding(s) — immediate remediation required"))
    if high:
        print(_c("HIGH", f"  ⚠  {high} HIGH severity finding(s)"))
    if not critical and not high:
        print(f"{GREEN}  ✓  No critical or high severity issues found{RESET}")
    print()


def save_json(findings, target_url, out_dir="reports", score_data=None):
    os.makedirs(out_dir, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    path = os.path.join(out_dir, f"scan_{ts}.json")
    counts = _counts(findings)
    report = {
        "target": target_url,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "risk": score_data or {},
        "summary": {s: counts.get(s, 0) for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]},
        "total_findings": len(findings),
        "findings": _sorted(findings),
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, default=str)
    return path


def save_markdown(findings, target_url, out_dir="reports"):
    os.makedirs(out_dir, exist_ok=True)
    ts_label = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    ts_file  = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    path = os.path.join(out_dir, f"scan_{ts_file}.md")
    counts = _counts(findings)
    sorted_findings = _sorted(findings)

    lines = [
        "# Supabase Security Scan Report",
        "",
        f"**Target:** {target_url}  ",
        f"**Scanned:** {ts_label}  ",
        f"**Total findings:** {len(findings)}",
        "",
        "## Summary",
        "",
        "| Severity | Count |",
        "|----------|-------|",
    ]
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        lines.append(f"| {sev} | {counts.get(sev, 0)} |")

    lines += ["", "---", "", "## All Findings", "", "| # | Severity | Issue |", "|---|----------|-------|"]
    for i, f in enumerate(sorted_findings, 1):
        issue = f.get("issue", "").replace("|", "\\|")
        lines.append(f"| {i} | **{f.get('severity')}** | {issue} |")

    lines += ["", "---", "", "## Detail", ""]
    for i, f in enumerate(sorted_findings, 1):
        sev = f.get("severity", "INFO")
        lines.append(f"### {i}. [{sev}] {f.get('issue', '')}")
        lines.append("")
        for k, v in f.items():
            if k in ("severity", "issue"):
                continue
            lines.append(f"- **{k}:** `{v}`")
        lines.append("")

    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))
    return path


def save_html(findings, target_url, out_dir="reports"):
    os.makedirs(out_dir, exist_ok=True)
    ts_label = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    ts_file  = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    path = os.path.join(out_dir, f"scan_{ts_file}.html")
    counts = _counts(findings)
    sorted_findings = _sorted(findings)

    severity_colors = {
        "CRITICAL": "#ef4444",
        "HIGH":     "#f97316",
        "MEDIUM":   "#eab308",
        "LOW":      "#3b82f6",
        "INFO":     "#6b7280",
    }

    rows = ""
    for i, f in enumerate(sorted_findings, 1):
        sev   = f.get("severity", "INFO")
        issue = f.get("issue", "")
        color = severity_colors.get(sev, "#6b7280")
        extra = "".join(
            f"<br><span style='color:#9ca3af;font-size:12px'><b>{k}:</b> {v}</span>"
            for k, v in f.items() if k not in ("severity", "issue")
        )
        rows += f"""<tr>
          <td style="color:#9ca3af;text-align:center">{i}</td>
          <td><span style="background:{color};color:#fff;padding:2px 8px;border-radius:4px;font-size:12px;font-weight:700">{sev}</span></td>
          <td>{issue}{extra}</td>
        </tr>"""

    summary_cards = ""
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        n = counts.get(sev, 0)
        color = severity_colors.get(sev, "#6b7280")
        summary_cards += f"""<div style="background:#1f2937;border-radius:8px;padding:16px 24px;text-align:center;min-width:100px">
          <div style="font-size:28px;font-weight:700;color:{color}">{n}</div>
          <div style="font-size:11px;color:#9ca3af;margin-top:4px;text-transform:uppercase;letter-spacing:.5px">{sev}</div>
        </div>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Supabase Scanner Report</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0 }}
  body {{ background: #111827; color: #e5e7eb; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; padding: 32px }}
  h1 {{ font-size: 22px; margin-bottom: 4px }}
  h2 {{ font-size: 15px; color: #9ca3af; font-weight: 400; margin-bottom: 24px }}
  .meta {{ color: #6b7280; font-size: 13px; margin-bottom: 24px }}
  .cards {{ display: flex; gap: 12px; margin-bottom: 32px; flex-wrap: wrap }}
  table {{ width: 100%; border-collapse: collapse; font-size: 13px }}
  th {{ background: #1f2937; color: #9ca3af; padding: 10px 14px; text-align: left; font-weight: 600; font-size: 11px; text-transform: uppercase; letter-spacing: .5px }}
  td {{ padding: 10px 14px; border-bottom: 1px solid #1f2937; vertical-align: top; line-height: 1.6 }}
  tr:hover td {{ background: #1f2937 }}
</style>
</head>
<body>
  <h1>🔍 Supabase Security Scan Report</h1>
  <h2>github.com/carl24tech/Supabase-Scanner</h2>
  <div class="meta">
    <b>Target:</b> {target_url} &nbsp;|&nbsp;
    <b>Scanned:</b> {ts_label} &nbsp;|&nbsp;
    <b>Total findings:</b> {len(findings)}
  </div>
  <div class="cards">{summary_cards}</div>
  <table>
    <thead><tr><th>#</th><th>Severity</th><th>Issue</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
</body>
</html>"""

    with open(path, "w", encoding="utf-8") as fh:
        fh.write(html)
    return path
