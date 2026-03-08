from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from ..utils import is_ignored


@dataclass
class ScanResult:
    target: Path
    python_files: int


def iter_python_files(root: Path) -> Iterable[Path]:
    for p in root.rglob("*.py"):
        if is_ignored(p):
            continue
        if p.is_file():
            yield p


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
