from __future__ import annotations

import argparse
from pathlib import Path

from .utils import make_run_outdir
from .scanners.scan import cmd_scan
from .scanners.bandit_scan import cmd_bandit
from .scanners.pip_audit import cmd_pip_audit
from .scanners.secrets import cmd_secrets
from .reporting.markdown import write_markdown_report


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
    scan.add_argument("target", nargs="?", default=".")
    scan.set_defaults(func=lambda args: cmd_scan(Path(args.target)))

    bandit = sub.add_parser("bandit", help="Run Bandit (Python SAST) against the target.")
    bandit.add_argument("target", nargs="?", default=".")
    bandit.add_argument("--severity", choices=["LOW", "MEDIUM", "HIGH"], default="LOW")
    bandit.add_argument("--out", default="reports")
    bandit.set_defaults(func=lambda args: cmd_bandit(Path(args.target), args.severity, Path(args.out)))

    pipaudit = sub.add_parser("pip-audit", help="Audit dependencies with pip-audit.")
    pipaudit.add_argument("target", nargs="?", default=".")
    pipaudit.add_argument("--out", default="reports")
    pipaudit.set_defaults(func=lambda args: cmd_pip_audit(Path(args.target), Path(args.out)))

    secrets = sub.add_parser("secrets", help="Scan for hardcoded secrets (regex patterns).")
    secrets.add_argument("target", nargs="?", default=".")
    secrets.add_argument("--out", default="reports")
    secrets.set_defaults(func=lambda args: cmd_secrets(Path(args.target), Path(args.out)))

    all_cmd = sub.add_parser("all", help="Run scan + bandit + pip-audit + secrets (writes reports).")
    all_cmd.add_argument("target", nargs="?", default=".")
    all_cmd.add_argument("--severity", choices=["LOW", "MEDIUM", "HIGH"], default="LOW")
    all_cmd.add_argument("--out", default="reports")
    all_cmd.set_defaults(func=lambda args: cmd_all(Path(args.target), args.severity, Path(args.out)))

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    rc = args.func(args)
    return 0 if rc is None else int(rc)
