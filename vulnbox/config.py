from __future__ import annotations

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
    "Hardcoded password": r"(?i)\b(pass(word)?|passwd|pwd)\b\s*=\s*['\"][^'\"]{4,}['\"]",
    "Hardcoded API key": r"(?i)\b(api[_-]?key)\b\s*=\s*['\"][^'\"]{8,}['\"]",
    "Hardcoded token/secret": r"(?i)\b(token|secret|access[_-]?token|refresh[_-]?token)\b\s*=\s*['\"][^'\"]{8,}['\"]",
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
