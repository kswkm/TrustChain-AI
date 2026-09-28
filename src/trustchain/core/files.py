"""파일 탐색 유틸리티 (제외 경로, 심볼릭 링크 미추적, 크기 제한)."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Iterator

MAX_FILE_BYTES = 2 * 1024 * 1024


def iter_files(root: Path, suffixes: tuple[str, ...] | None = None, exclude: list[str] | None = None) -> Iterator[Path]:
    exclude_set = set(exclude or [])
    root = Path(root)
    if root.is_file():
        if suffixes is None or root.suffix.lower() in suffixes:
            yield root
        return
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [d for d in dirnames if d not in exclude_set and (not d.startswith(".") or d == ".github")]
        for name in filenames:
            p = Path(dirpath) / name
            if p.is_symlink():
                continue
            if suffixes is not None and p.suffix.lower() not in suffixes:
                continue
            yield p


def read_text(path: Path, limit: int = MAX_FILE_BYTES) -> str | None:
    try:
        if path.stat().st_size > limit:
            return None
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def rel(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()
