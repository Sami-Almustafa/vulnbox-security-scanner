from __future__ import annotations

import json
from pathlib import Path

from .config import IGNORE_DIRS


def write_report(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def load_json(path: Path):
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def make_run_outdir(base: Path) -> Path:
    # keeps same timestamp format you used
    from datetime import datetime
    stamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    return base / stamp


def is_ignored(path: Path) -> bool:
    return any(part in IGNORE_DIRS for part in path.parts)
