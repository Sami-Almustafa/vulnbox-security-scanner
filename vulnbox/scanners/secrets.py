from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Iterable

from ..config import SECRET_PATTERNS, REMEDIATIONS
from ..utils import is_ignored, write_report


def iter_text_files(root: Path) -> Iterable[Path]:
    exts = {".py", ".env", ".txt", ".yml", ".yaml", ".json", ".ini", ".cfg", ".toml"}
    for p in root.rglob("*"):
        if is_ignored(p):
            continue
        if p.is_file() and p.suffix.lower() in exts:
            yield p


def cmd_secrets(target: Path, outdir: Path) -> int:
    if not target.exists():
        print(f"[!] Path not found: {target}")
        return 2

    findings: list[dict[str, object]] = []

    for file_path in iter_text_files(target):
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

        for rule_name, pattern in SECRET_PATTERNS.items():
            for m in re.finditer(pattern, content):
                line_no = content.count("\n", 0, m.start()) + 1
                findings.append({
                    "type": rule_name,
                    "file": str(file_path),
                    "line": line_no,
                    "recommendation": REMEDIATIONS.get(rule_name, "Remove hardcoded secrets from source code."),
                })

    report_json = outdir / "secrets.json"
    report_txt = outdir / "secrets.txt"
    write_report(report_json, json.dumps(findings, indent=2))

    if not findings:
        write_report(report_txt, "\n".join([
            "VulnBox Report: Secrets",
            f"Target: {target.resolve()}",
            "Findings: 0",
        ]))
        print("[+] Secrets scan: no hardcoded secrets found.")
        print(f"[+] Saved: {report_json}")
        print(f"[+] Saved: {report_txt}")
        return 0

    lines = [
        "VulnBox Report: Secrets",
        f"Target: {target.resolve()}",
        f"Findings: {len(findings)}",
        "",
    ]
    for f in findings[:200]:
        lines.append(f"{f['type']} -> {f['file']}:{f['line']}")
        lines.append(f"    Fix: {f.get('recommendation')}")
        lines.append("")

    write_report(report_txt, "\n".join(lines))

    print(f"[!] Secrets scan: {len(findings)} potential issues found.")
    print(f"[+] Saved: {report_json}")
    print(f"[+] Saved: {report_txt}")
    return 1
