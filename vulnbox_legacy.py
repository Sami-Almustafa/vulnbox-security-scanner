from __future__ import annotations
from vulnbox.cli import main

if __name__ == "__main__":
    raise SystemExit(main())

import re
import argparse
import json
import subprocess
from datetime import datetime

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


IGNORE_DIRS = {
    ".venv", "venv",
    "__pycache__",
    ".git",
    "node_modules",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".idea",
    ".vscode",
}

SECRET_PATTERNS: dict[str, str] = {
    # simple assignment patterns (Python)
    "Hardcoded password": r"(?i)\b(pass(word)?|passwd|pwd)\b\s*=\s*['\"][^'\"]{4,}['\"]",
    "Hardcoded API key": r"(?i)\b(api[_-]?key)\b\s*=\s*['\"][^'\"]{8,}['\"]",
    "Hardcoded token/secret": r"(?i)\b(token|secret|access[_-]?token|refresh[_-]?token)\b\s*=\s*['\"][^'\"]{8,}['\"]",

    # high-signal credential formats
    "AWS Access Key ID": r"\bAKIA[0-9A-Z]{16}\b",
    "Private key block": r"-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----",
}

REMEDIATIONS = {
    "Hardcoded password": "Use environment variables or a secrets manager instead of hardcoding passwords.",
    "Hardcoded API key": "Store API keys in environment variables or external configuration files.",
    "Hardcoded token/secret": "Move tokens to secure storage and rotate exposed credentials.",
    "AWS Access Key ID": "Remove the key immediately and use IAM roles or environment variables.",
    "Private key block": "Never store private keys in source code; use secure key storage.",
}
BANDIT_FIXES = {
    "B105": "Do not hardcode passwords. Use environment variables or a secrets manager.",
    "B106": "Do not hardcode passwords in function arguments. Use secure configuration.",
    "B107": "Avoid hardcoded passwords in defaults. Use environment variables.",
    "B301": "Use safe serialization formats (e.g., JSON). Avoid pickle with untrusted data.",
    "B602": "Avoid shell=True. Pass args as a list and validate inputs.",
    "B603": "Validate inputs passed into subprocess and use allowlists where possible.",
}



@dataclass
class ScanResult:
    target: Path
    python_files: int


def iter_python_files(root: Path) -> Iterable[Path]:
    """Yield .py files under root, excluding common junk directories."""
    for p in root.rglob("*.py"):
        if any(part in IGNORE_DIRS for part in p.parts):
            continue
        if p.is_file():
            yield p


def write_report(path: Path, content: str) -> None:
    """Write content to path, creating parent directories if needed."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")

def load_json(path: Path):
    """Load JSON file safely. Returns None on failure."""
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def write_markdown_report(
    outdir: Path,
    target: Path,
    severity: str,
    bandit_rc: int,
    audit_rc: int,
    secrets_rc: int,
) -> None:
    # Load generated JSONs (written earlier by scanners)
    bandit_data = load_json(outdir / "bandit.json") or {}
    bandit_results = bandit_data.get("results", [])

    audit_data = load_json(outdir / "pip_audit.json") or []
    secrets_data = load_json(outdir / "secrets.json") or []

    lines = [
        "# VulnBox Security Scan Report",
        "",
        f"**Target:** `{target.resolve()}`",
        f"**Scan time:** `{outdir.name}`",
        f"**Bandit minimum severity:** `{severity}`",
        "",
        "## Summary",
        "",
        f"- **Bandit (code analysis):** {'Issues found' if bandit_rc == 1 else 'No issues found'}",
        f"- **pip-audit (dependencies):** {'Issues found' if audit_rc == 1 else 'No issues found'}",
        f"- **Secrets (hardcoded credentials):** {'Issues found' if secrets_rc == 1 else 'No issues found'}",
        "",
        "## Key Findings & Mitigations",
        "",
    ]
    # =========================
    # Key Findings & Mitigations
    # =========================
    lines += ["## Key Findings & Mitigations", ""]
    # -------------------------
    # Bandit findings
    # -------------------------
    lines += ["### Bandit (Code Issues)", ""]

    bandit_results = bandit_results if isinstance(bandit_results, list) else []

    if not bandit_results:
        lines += ["No Bandit issues were detected.", ""]
    else:
        # Sort by severity (HIGH → LOW)
        sev_order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}
        bandit_results = sorted(
            bandit_results,
            key=lambda r: sev_order.get(r.get("issue_severity", "LOW"), 0),
            reverse=True,
        )

        shown = 0
        for r in bandit_results:
            test_id = r.get("test_id", "UNKNOWN")
            fix = BANDIT_FIXES.get(
                test_id,
                "Review the code and apply secure coding best practices relevant to this issue."
            )

            lines += [
                f"- **{r.get('issue_severity','?')}/{r.get('issue_confidence','?')} {test_id}**: "
                f"{(r.get('issue_text') or '').strip()}  ",
                f"  Location: `{r.get('filename','?')}:{r.get('line_number','?')}`  ",
                f"  Recommendation: {fix}",
                "",
            ]

            shown += 1
            if shown >= 10:
                break

        remaining = max(0, len(bandit_results) - shown)
        if remaining:
            lines += [
                f"_Output capped: {remaining} more Bandit findings are available in `bandit.json`._",
                "",
            ]

    # -------------------------
    # pip-audit findings
    # -------------------------
    lines += ["### pip-audit (Dependency Issues)", ""]
    total_audit_vulns = 0
    if isinstance(audit_data, list):
        total_audit_vulns = sum(len(d.get("vulns", [])) for d in audit_data if isinstance(d, dict))

    if not audit_data or total_audit_vulns == 0:
        lines += ["No vulnerable dependencies were detected by pip-audit.", ""]
    else:
        shown = 0
        for dep in audit_data:
            if not isinstance(dep, dict):
                continue
            name = dep.get("name", "?")
            version = dep.get("version", "?")
            for v in dep.get("vulns", []):
                if not isinstance(v, dict):
                    continue
                vid = v.get("id", "?")
                fixes = v.get("fix_versions", [])
                fix_txt = ", ".join(fixes) if fixes else "Upgrade to the latest patched version."
                lines += [
                    f"- **{name}=={version}** → `{vid}`  ",
                    f"  Recommendation: Upgrade ({fix_txt})",
                    "",
                ]
                shown += 1
                if shown >= 10:
                    break
            if shown >= 10:
                break

        remaining = max(0, total_audit_vulns - shown)
        if remaining:
            lines += [f"_Output capped: {remaining} more dependency issues are available in `pip_audit.json`._", ""]

    # -------------------------
    # Secrets findings
    # -------------------------
    lines += ["### Secrets (Hardcoded Credentials)", ""]

    secrets_data = secrets_data if isinstance(secrets_data, list) else []

    # Build set of Bandit locations to avoid duplicate password reports
    bandit_locs = {
        (r.get("filename"), r.get("line_number"))
        for r in bandit_results
        if isinstance(r, dict)
    }

    if not secrets_data:
        lines += ["No hardcoded secrets were detected.", ""]
    else:
        shown = 0
        for f in secrets_data:
            if not isinstance(f, dict):
                continue

            # Skip duplicate password findings already covered by Bandit
            if (
                f.get("type") == "Hardcoded password"
                and (f.get("file"), f.get("line")) in bandit_locs
            ):
                continue

            lines += [
                f"- **{f.get('type','?')}**  ",
                f"  Location: `{f.get('file','?')}:{f.get('line','?')}`  ",
                f"  Recommendation: {f.get('recommendation', 'Remove hardcoded secrets from source code.')}",
                "",
            ]

            shown += 1
            if shown >= 10:
                break

        remaining = max(0, len(secrets_data) - shown)
        if remaining:
            lines += [
                f"_Output capped: {remaining} more secret findings are available in `secrets.json`._",
                "",
            ]

    # Footer
    lines += [
        "## Generated Files",
        "",
        "- `bandit.json` – Raw Bandit findings (JSON)",
        "- `bandit.txt` – Human-readable Bandit summary",
        "- `pip_audit.json` – Raw dependency audit results",
        "- `pip_audit.txt` – Human-readable dependency summary",
        "- `secrets.json` – Raw secrets findings (JSON)",
        "- `secrets.txt` – Human-readable secrets summary",
        "",
        "## Notes",
        "",
        "- This tool performs **static analysis only**.",
        "- Findings depend on the rulesets used by Bandit and pip-audit, and the regex patterns used for secrets detection.",
        "- Absence of findings does **not** guarantee absence of vulnerabilities.",
        "",
        "## Ethics & Scope",
        "",
        "VulnBox is designed for **defensive security analysis** of codebases owned by or authorised for the user.",
        "No exploitation or active attacks are performed.",
        "",
    ]

    report_md = outdir / "report.md"
    write_report(report_md, "\n".join(lines))



def cmd_scan(target: Path) -> int:
    if not target.exists():
        print(f"[!] Path not found: {target}")
        return 2

    py_files = list(iter_python_files(target))
    result = ScanResult(target=target.resolve(), python_files=len(py_files))

    print("[+] VulnBox online.")
    print(f"[+] Target: {result.target}")
    print(f"[+] Python files found (filtered): {result.python_files}")

    if py_files:
        print("\n[+] Sample files:")
        for f in py_files[:5]:
            print(f"    - {f}")

    return 0


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

    # 0 = no issues, 1 = issues found, 2 = error
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

    # Save raw JSON report
    report_json = outdir / "bandit.json"
    write_report(report_json, json.dumps(data, indent=2))

    results = data.get("results", [])
    if not results:
        report_txt = outdir / "bandit.txt"
        write_report(
            report_txt,
            "\n".join(
                [
                    "VulnBox Report: Bandit",
                    f"Target: {target.resolve()}",
                    f"Min severity: {min_severity}",
                    "Total issues: 0",
                    "Shown issues: 0",
                ]
            ),
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

    # Write text summary
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

    print(f"[+] Bandit issues found: {len(results)} (showing {len(filtered)} with severity >= {min_severity})")

    for r in filtered[:20]:
        file_path = r.get("filename", "?")
        line = r.get("line_number", "?")
        sev = r.get("issue_severity", "?")
        conf = r.get("issue_confidence", "?")
        test_id = r.get("test_id", "?")
        text = (r.get("issue_text") or "").strip()

        print(f"\n[!] {sev}/{conf} {test_id}: {text}")
        print(f"    -> {file_path}:{line}")

    if len(filtered) > 20:
        print(f"\n[+] Output capped: {len(filtered) - 20} more findings not shown.")

    return 1 if filtered else 0


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
        print("Then run:")
        print("    python vulnbox.py pip-audit <target>")
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

    # Normalize pip-audit JSON across versions
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

    # Save raw JSON report (normalized list)
    report_json = outdir / "pip_audit.json"
    write_report(report_json, json.dumps(data, indent=2))

    total_vulns = sum(len(dep.get("vulns", [])) for dep in data)

    # Write text summary (always)
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

    print(f"[!] pip-audit: vulnerable dependencies found: {total_vulns}\n")

    # Also print a compact summary to terminal
    shown = 0
    for dep in data:
        name = dep.get("name", "?")
        version = dep.get("version", "?")
        for v in dep.get("vulns", []):
            vid = v.get("id", "?")
            fix = v.get("fix_versions", [])
            fix_txt = f" | fix: {', '.join(fix)}" if fix else ""
            desc = (v.get("description") or "").strip()

            print(f"[!] {name}=={version} -> {vid}{fix_txt}")
            if desc:
                print(f"    {desc[:160]}{'...' if len(desc) > 160 else ''}")

            shown += 1
            if shown >= 20:
                print("\n[+] Output capped (20).")
                return 1

    return 1


def iter_text_files(root: Path) -> Iterable[Path]:
    """Yield files we want to scan for secrets (start simple: .py, .env, .txt, .yml/.yaml, .json)."""
    exts = {".py", ".env", ".txt", ".yml", ".yaml", ".json", ".ini", ".cfg", ".toml"}
    for p in root.rglob("*"):
        if any(part in IGNORE_DIRS for part in p.parts):
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
                    "recommendation": REMEDIATIONS.get(rule_name, "Remove hardcoded secrets from source code.")

                })

    # Save reports
    report_json = outdir / "secrets.json"
    report_txt = outdir / "secrets.txt"
    write_report(report_json, json.dumps(findings, indent=2))

    if not findings:
        write_report(
            report_txt,
            "\n".join([
                "VulnBox Report: Secrets",
                f"Target: {target.resolve()}",
                "Findings: 0",
            ])
        )
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
        lines.append(f"    Fix: {f.get('recommendation', 'Remove hardcoded secrets from source code.')}")
        lines.append("")


    write_report(report_txt, "\n".join(lines))

    print(f"[!] Secrets scan: {len(findings)} potential issues found.")
    for f in findings[:20]:
        print(f"    {f['type']} -> {f['file']}:{f['line']}")
    if len(findings) > 20:
        print("[+] Output capped (20).")

    print(f"[+] Saved: {report_json}")
    print(f"[+] Saved: {report_txt}")
    return 1


def make_run_outdir(base: Path) -> Path:
    stamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    return base / stamp


def cmd_all(target: Path, severity: str, outdir: Path) -> int:
    run_outdir = make_run_outdir(outdir)

    print("[+] Running VulnBox: all checks")
    print(f"[+] Reports: {run_outdir}\n")

    rc_scan = cmd_scan(target)
    rc_bandit = cmd_bandit(target, severity, run_outdir)
    rc_audit = cmd_pip_audit(target, run_outdir)
    rc_secrets = cmd_secrets(target, run_outdir)

    write_markdown_report(
        outdir=run_outdir,
        target=target,
        severity=severity,
        bandit_rc=rc_bandit,
        audit_rc=rc_audit,
        secrets_rc=rc_secrets,
    )

    print(f"[+] Markdown report generated: {run_outdir / 'report.md'}")

    if 2 in (rc_scan, rc_bandit, rc_audit, rc_secrets):
        return 2
    if 1 in (rc_scan, rc_bandit, rc_audit, rc_secrets):
        return 1
    return 0




def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vulnbox",
        description="Developer-focused security scanner (CLI).",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Find and list Python files (filtered).")
    scan.add_argument("target", nargs="?", default=".", help="Path to project folder (default: current folder)")
    scan.set_defaults(func=lambda args: cmd_scan(Path(args.target)))

    bandit = sub.add_parser("bandit", help="Run Bandit (Python SAST) against the target.")
    bandit.add_argument("target", nargs="?", default=".", help="Path to project folder (default: current folder)")
    bandit.add_argument("--severity", choices=["LOW", "MEDIUM", "HIGH"], default="LOW",
                        help="Minimum severity to report (default: LOW)")
    bandit.add_argument("--out", default="reports", help="Output directory for reports (default: reports)")
    bandit.set_defaults(func=lambda args: cmd_bandit(Path(args.target), args.severity, Path(args.out)))

    pipaudit = sub.add_parser("pip-audit", help="Audit dependencies with pip-audit.")
    pipaudit.add_argument("target", nargs="?", default=".", help="Path to project folder (default: current folder)")
    pipaudit.add_argument("--out", default="reports", help="Output directory for reports (default: reports)")
    pipaudit.set_defaults(func=lambda args: cmd_pip_audit(Path(args.target), Path(args.out)))

    secrets = sub.add_parser("secrets", help="Scan for hardcoded secrets (regex patterns).")
    secrets.add_argument("target", nargs="?", default=".", help="Path to project folder (default: current folder)")
    secrets.add_argument("--out", default="reports", help="Output directory for reports (default: reports)")
    secrets.set_defaults(func=lambda args: cmd_secrets(Path(args.target), Path(args.out)))


    all_cmd = sub.add_parser("all", help="Run scan + bandit + pip-audit (writes reports).")
    all_cmd.add_argument("target", nargs="?", default=".", help="Path to project folder (default: current folder)")
    all_cmd.add_argument("--severity", choices=["LOW", "MEDIUM", "HIGH"], default="LOW",
                         help="Minimum Bandit severity to report (default: LOW)")
    all_cmd.add_argument("--out", default="reports", help="Output directory for reports (default: reports)")
    all_cmd.set_defaults(func=lambda args: cmd_all(Path(args.target), args.severity, Path(args.out)))

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    rc = args.func(args)
    return 0 if rc is None else int(rc)


if __name__ == "__main__":
    raise SystemExit(main())
