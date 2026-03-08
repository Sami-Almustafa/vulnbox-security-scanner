from __future__ import annotations

import json
import subprocess
from pathlib import Path

from ..config import IGNORE_DIRS
from ..utils import write_report


def cmd_bandit(target: Path, min_severity: str, outdir: Path) -> int:
    if not target.exists():
        print(f"[!] Path not found: {target}")
        return 2

    cmd = [
        "bandit",
        "-r", str(target),
        "-f", "json",
        "--quiet",
        "--exclude", ",".join(list(IGNORE_DIRS) + ["vulnbox.py"]),
    ]

    print("[+] Running Bandit...")
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True)
    except FileNotFoundError:
        print("[!] Bandit not found. Install with: python -m pip install bandit")
        return 2

    if proc.returncode == 2:
        print("[!] Bandit error:")
        print(proc.stderr.strip() or proc.stdout.strip())
        return 2

    if not proc.stdout.strip():
        print("[+] Bandit: no issues found.")
        return 0

    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        print("[!] Bandit output was not valid JSON.")
        print(proc.stdout[:800])
        return 2

    report_json = outdir / "bandit.json"
    write_report(report_json, json.dumps(data, indent=2))

    results = data.get("results", [])
    if not results:
        report_txt = outdir / "bandit.txt"
        write_report(
            report_txt,
            "\n".join([
                "VulnBox Report: Bandit",
                f"Target: {target.resolve()}",
                f"Min severity: {min_severity}",
                "Total issues: 0",
                "Shown issues: 0",
            ]),
        )
        print("[+] Bandit: no issues found.")
        print(f"[+] Saved: {report_json}")
        print(f"[+] Saved: {report_txt}")
        return 0

    severity_order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}
    threshold = severity_order[min_severity]

    filtered = [
        r for r in results
        if severity_order.get(r.get("issue_severity", "LOW"), 0) >= threshold
    ]

    summary_lines = [
        "VulnBox Report: Bandit",
        f"Target: {target.resolve()}",
        f"Min severity: {min_severity}",
        f"Total issues: {len(results)}",
        f"Shown issues: {len(filtered)}",
        "",
    ]
    for r in filtered[:200]:
        summary_lines.append(
            f"{r.get('issue_severity','?')}/{r.get('issue_confidence','?')} "
            f"{r.get('test_id','?')} {(r.get('issue_text') or '').strip()} "
            f"({r.get('filename','?')}:{r.get('line_number','?')})"
        )

    report_txt = outdir / "bandit.txt"
    write_report(report_txt, "\n".join(summary_lines))

    print(f"[+] Saved: {report_json}")
    print(f"[+] Saved: {report_txt}")

    return 1 if filtered else 0
