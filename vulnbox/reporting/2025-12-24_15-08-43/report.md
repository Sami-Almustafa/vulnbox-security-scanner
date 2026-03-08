# VulnBox Security Scan Report

**Target:** `C:\Users\User\Desktop\vulnbox`
**Scan time:** `2025-12-24_15-08-43`
**Bandit minimum severity:** `LOW`

## Summary

- **Bandit (code analysis):** Issues found
- **pip-audit (dependencies):** No issues found
- **Secrets (hardcoded credentials):** Issues found

## Key Findings & Mitigations

### Bandit (Code Issues)

- **LOW/MEDIUM B105**: Possible hardcoded password: 'admin123'  
  Location: `.\test\demo.py:1`  
  Recommendation: Do not hardcode passwords. Use environment variables or a secrets manager.

- **LOW/HIGH B404**: Consider possible security implications associated with the subprocess module.  
  Location: `.\vulnbox\scanners\bandit_scan.py:4`  
  Recommendation: Review and apply secure coding best practices for this issue.

- **LOW/HIGH B603**: subprocess call - check for execution of untrusted input.  
  Location: `.\vulnbox\scanners\bandit_scan.py:26`  
  Recommendation: Validate inputs passed into subprocess and use allowlists where possible.

- **LOW/HIGH B404**: Consider possible security implications associated with the subprocess module.  
  Location: `.\vulnbox\scanners\pip_audit.py:4`  
  Recommendation: Review and apply secure coding best practices for this issue.

- **LOW/HIGH B603**: subprocess call - check for execution of untrusted input.  
  Location: `.\vulnbox\scanners\pip_audit.py:38`  
  Recommendation: Validate inputs passed into subprocess and use allowlists where possible.

- **LOW/HIGH B112**: Try, Except, Continue detected.  
  Location: `.\vulnbox\scanners\secrets.py:31`  
  Recommendation: Review and apply secure coding best practices for this issue.

- **LOW/HIGH B404**: Consider possible security implications associated with the subprocess module.  
  Location: `.\vulnbox_legacy.py:10`  
  Recommendation: Review and apply secure coding best practices for this issue.

- **LOW/HIGH B603**: subprocess call - check for execution of untrusted input.  
  Location: `.\vulnbox_legacy.py:318`  
  Recommendation: Validate inputs passed into subprocess and use allowlists where possible.

- **LOW/HIGH B603**: subprocess call - check for execution of untrusted input.  
  Location: `.\vulnbox_legacy.py:443`  
  Recommendation: Validate inputs passed into subprocess and use allowlists where possible.

- **LOW/HIGH B112**: Try, Except, Continue detected.  
  Location: `.\vulnbox_legacy.py:566`  
  Recommendation: Review and apply secure coding best practices for this issue.

### pip-audit (Dependency Issues)

No vulnerable dependencies were detected by pip-audit.

### Secrets (Hardcoded Credentials)

- **Hardcoded password**  
  Location: `test\demo.py:1`  
  Recommendation: Use environment variables or a secrets manager instead of hardcoding passwords.

- **Hardcoded API key**  
  Location: `test\demo.py:2`  
  Recommendation: Store API keys in environment variables or external configuration files.

- **AWS Access Key ID**  
  Location: `test\demo.py:4`  
  Recommendation: Remove the key immediately and use IAM roles or environment variables.

## Generated Files

- `bandit.json` – Raw Bandit findings (JSON)
- `bandit.txt` – Human-readable Bandit summary
- `pip_audit.json` – Raw dependency audit results
- `pip_audit.txt` – Human-readable dependency summary
- `secrets.json` – Raw secrets findings (JSON)
- `secrets.txt` – Human-readable secrets summary

## Notes

- This tool performs **static analysis only**.
- Absence of findings does **not** guarantee absence of vulnerabilities.

## Ethics & Scope

VulnBox is designed for **defensive security analysis** of codebases owned by or authorised for the user.
No exploitation or active attacks are performed.
