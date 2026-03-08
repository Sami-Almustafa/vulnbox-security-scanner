# 🔐 VulnBox

> A lightweight, offline security scanner for Python developers

**VulnBox** is a command-line tool that helps developers identify common security issues in Python projects.  
It performs static analysis locally and provides **clear, educational guidance** on how to fix detected problems.

⚠️ Designed for **defensive and authorised use only**.

---

## ✨ Features

- 🔍 **Static code analysis** using Bandit  
- 📦 **Dependency vulnerability scanning** with pip-audit  
- 🔑 **Hardcoded secrets detection** using regex-based rules  
- 📴 **Fully offline** — no cloud services required  
- 📄 **Readable reports** (TXT & JSON)  
- 🎓 **Actionable remediation advice**

---

## 🧪 Supported Scans

| Scan | Description |
|------|-------------|
| Code Analysis | Detects insecure coding patterns |
| Dependency Scan | Finds vulnerable third-party packages |
| Secrets Scan | Identifies hardcoded passwords and API keys |

---

## ⚙️ Installation

### Requirements
- Python **3.10+**
- pip

### Setup
```bash
pip install -r requirements.txt
```

---

## 🚀 Usage

### Run all scans
```bash
python -m vulnbox all <target_path> --severity LOW --out reports
```

### Secrets scan only
```bash
python -m vulnbox secrets <target_path> --out reports
```

### Dependency scan only
```bash
python -m vulnbox deps <target_path> --out reports
```

---

## 📂 Output Structure

Each scan creates a **timestamped report directory**:

```text
reports/
 └─ 2025-12-24_15-13-14/
    ├─ bandit.json
    ├─ bandit.txt
    ├─ pip_audit.json
    ├─ pip_audit.txt
    ├─ secrets.json
    └─ secrets.txt
```

A summary is also printed directly to the terminal.

---

## 🧠 How It Works

- **Bandit** → AST-based static analysis for insecure code patterns  
- **pip-audit** → CVE lookup for vulnerable dependencies  
- **Secrets Scanner** → Regex-based pattern matching for credentials  

Each finding includes a **short explanation and fix recommendation**.

---

## 🧪 Testing

VulnBox was tested using **controlled Python test projects** containing known vulnerabilities such as:

- hardcoded credentials  
- unsafe subprocess usage  
- weak cryptographic functions  
- outdated dependencies  

No real or sensitive data was used during testing.

---

## ⚠️ Limitations

- Python projects only  
- Static analysis only (no runtime context)  
- Regex-based secret detection may produce false positives  
- Not a replacement for professional security audits  

---

## 🛡️ Ethics & Scope

VulnBox is intended for **educational and defensive security analysis**.

- No exploitation  
- No network scanning  
- No data exfiltration  

Users must ensure they are authorised to scan the target codebase.

---

## 👤 Author

**Sami Al Mustafa**  
BSc Computer Science  
Brunel University London
