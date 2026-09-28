"""import 구문 분석 : 코드가 실제로 사용하는 외부 모듈 목록 추출.

F2 에서 '코드와 이름이 맞지 않는 패키지'(requirements 에는 있는데 코드에서 쓰지
않거나, 코드에서 쓰는데 선언되지 않은 모듈)를 찾고, F11 우선순위 계산에서
'실제 사용 여부' 판단에 쓰인다.
"""

from __future__ import annotations

import ast
import json
import sys
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path

from packaging.utils import canonicalize_name

from trustchain.core.files import iter_files, read_text, rel


@dataclass
class ImportUse:
    module: str  # 최상위 모듈명
    files: list[tuple[str, int]] = field(default_factory=list)


def _import_map() -> dict[str, list[str]]:
    raw = json.loads(resources.files("trustchain.data").joinpath("import_map.json").read_text(encoding="utf-8"))
    return {k: (v if isinstance(v, list) else [v]) for k, v in raw.items()}


IMPORT_MAP = _import_map()
STDLIB = set(sys.stdlib_module_names) | {"__future__"}


def candidate_distributions(module: str) -> list[str]:
    """import 이름에 대응할 수 있는 배포 패키지 이름 후보."""
    if module in IMPORT_MAP:
        return [canonicalize_name(d) for d in IMPORT_MAP[module]]
    return [canonicalize_name(module)]


def local_modules(root: Path, exclude: list[str]) -> set[str]:
    names: set[str] = set()
    for base in (root, root / "src"):
        if not base.is_dir():
            continue
        for p in base.iterdir():
            if p.name in exclude or p.name.startswith("."):
                continue
            if p.is_dir() and ((p / "__init__.py").exists() or any(p.glob("*.py"))):
                names.add(p.name)
            elif p.suffix == ".py":
                names.add(p.stem)
    # 하위 디렉터리의 모듈도 스크립트 실행 시 import 될 수 있음
    for p in iter_files(root, (".py",), exclude):
        names.add(p.stem)
    return names


def collect_imports(root: Path, exclude: list[str]) -> dict[str, ImportUse]:
    root = Path(root)
    local = local_modules(root, exclude)
    uses: dict[str, ImportUse] = {}
    for p in iter_files(root, (".py",), exclude):
        text = read_text(p)
        if text is None:
            continue
        try:
            tree = ast.parse(text)
        except (SyntaxError, ValueError):
            continue
        for node in ast.walk(tree):
            mods: list[str] = []
            if isinstance(node, ast.Import):
                mods = [a.name.split(".")[0] for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                mods = [node.module.split(".")[0]]
            for m in mods:
                if m in STDLIB or m in local:
                    continue
                uses.setdefault(m, ImportUse(m)).files.append((rel(p, root), node.lineno))
    return uses
