from __future__ import annotations

import json
import subprocess
from pathlib import Path

from ..utils import write_report


def cmd_pip_audit(target: Path, outdir: Path) -> int:
    if not target.exists():
        print(f"[!] Path not found: {target}")
        return 2

    target = target.resolve()
    req = target / "requirements.txt"
    pyproject = target / "pyproject.toml"

    if req.exists():
        cmd = ["pip-audit", "-r", str(req), "-f", "json"]
        mode = f"requirements file: {req.name}"
        cwd = str(target)
    elif pyproject.exists():
        cmd = ["pip-audit", "-f", "json"]
        mode = "project/env (no requirements.txt found; pyproject.toml exists)"
        cwd = str(target)
    else:
        print("[!] No requirements.txt or pyproject.toml found in target.")
        print("[!] Fix: in your project folder run:")
        print("    pip freeze > requirements.txt")
        return 2

    print("[+] Running pip-audit...")
    print(f"[+] Target: {target}")
    print(f"[+] Mode: {mode}")

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, cwd=cwd)
    except FileNotFoundError:
        print("[!] pip-audit not found. Install with: python -m pip install pip-audit")
        return 2

    out = (proc.stdout or "").strip()
    err = (proc.stderr or "").strip()

    if proc.returncode != 0 and not out:
        print("[!] pip-audit error:")
        print(err)
        return 2

    try:
        data = json.loads(out) if out else []
    except json.JSONDecodeError:
        print("[!] Could not parse pip-audit JSON output.")
        print(out[:800])
        return 2

    if isinstance(data, str):
        try:
            data = json.loads(data)
        except json.JSONDecodeError:
            print("[!] pip-audit returned a string that isn't JSON.")
            print(data[:800])
            return 2

    if isinstance(data, dict):
        if "dependencies" in data and isinstance(data["dependencies"], list):
            data = data["dependencies"]
        elif "results" in data and isinstance(data["results"], list):
            data = data["results"]
        else:
            print("[!] Unexpected pip-audit JSON object format.")
            print(str(data)[:800])
            return 2

    if not isinstance(data, list):
        print("[!] Unexpected pip-audit JSON format (not a list).")
        print(str(data)[:800])
        return 2

    report_json = outdir / "pip_audit.json"
    write_report(report_json, json.dumps(data, indent=2))

    total_vulns = sum(len(dep.get("vulns", [])) for dep in data)

    summary_lines = [
        "VulnBox Report: pip-audit",
        f"Target: {target}",
        f"Mode: {mode}",
        f"Total vulnerabilities: {total_vulns}",
        "",
    ]
    for dep in data:
        name = dep.get("name", "?")
        version = dep.get("version", "?")
        for v in dep.get("vulns", []):
            vid = v.get("id", "?")
            fixes = v.get("fix_versions", [])
            fix_txt = ", ".join(fixes) if fixes else "N/A"
            summary_lines.append(f"{name}=={version} -> {vid} | fix: {fix_txt}")

    report_txt = outdir / "pip_audit.txt"
    write_report(report_txt, "\n".join(summary_lines))

    print(f"[+] Saved: {report_json}")
    print(f"[+] Saved: {report_txt}")

    if total_vulns == 0:
        print("[+] pip-audit: no vulnerable dependencies found.")
        return 0

    return 1
