from __future__ import annotations

from pathlib import Path

from ..config import BANDIT_FIXES
from ..utils import load_json, write_report


def write_markdown_report(
    outdir: Path,
    target: Path,
    severity: str,
    bandit_rc: int,
    audit_rc: int,
    secrets_rc: int,
) -> None:
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

    # Bandit
    lines += ["### Bandit (Code Issues)", ""]
    bandit_results = bandit_results if isinstance(bandit_results, list) else []
    if not bandit_results:
        lines += ["No Bandit issues were detected.", ""]
    else:
        sev_order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}
        bandit_results = sorted(
            bandit_results,
            key=lambda r: sev_order.get(r.get("issue_severity", "LOW"), 0),
            reverse=True,
        )
        shown = 0
        for r in bandit_results:
            test_id = r.get("test_id", "UNKNOWN")
            fix = BANDIT_FIXES.get(test_id, "Review and apply secure coding best practices for this issue.")
            lines += [
                f"- **{r.get('issue_severity','?')}/{r.get('issue_confidence','?')} {test_id}**: {(r.get('issue_text') or '').strip()}  ",
                f"  Location: `{r.get('filename','?')}:{r.get('line_number','?')}`  ",
                f"  Recommendation: {fix}",
                "",
            ]
            shown += 1
            if shown >= 10:
                break
        remaining = max(0, len(bandit_results) - shown)
        if remaining:
            lines += [f"_Output capped: {remaining} more Bandit findings are available in `bandit.json`._", ""]

    # pip-audit
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

    # Secrets
    lines += ["### Secrets (Hardcoded Credentials)", ""]
    secrets_data = secrets_data if isinstance(secrets_data, list) else []
    if not secrets_data:
        lines += ["No hardcoded secrets were detected.", ""]
    else:
        shown = 0
        for f in secrets_data:
            if not isinstance(f, dict):
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
            lines += [f"_Output capped: {remaining} more secret findings are available in `secrets.json`._", ""]

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
        "- Absence of findings does **not** guarantee absence of vulnerabilities.",
        "",
        "## Ethics & Scope",
        "",
        "VulnBox is designed for **defensive security analysis** of codebases owned by or authorised for the user.",
        "No exploitation or active attacks are performed.",
        "",
    ]

    write_report(outdir / "report.md", "\n".join(lines))
