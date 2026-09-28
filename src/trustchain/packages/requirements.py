"""requirements.txt / pyproject.toml 의존성 파싱."""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name


@dataclass
class Dependency:
    name: str  # 정규화된 이름 (PEP 503)
    raw_name: str  # 파일에 적힌 그대로 (대소문자·구분자 위장 탐지에 사용)
    specifier: str = ""
    pinned_version: str | None = None
    hashes: list[str] = field(default_factory=list)
    url: str | None = None  # git+/http 직접 참조
    source: str = ""
    line: int | None = None

    @property
    def is_pinned(self) -> bool:
        return self.pinned_version is not None


def _pinned(req: Requirement) -> str | None:
    specs = list(req.specifier)
    if len(specs) == 1 and specs[0].operator in ("==", "===") and "*" not in specs[0].version:
        return specs[0].version
    return None


def parse_requirement_line(line: str, source: str = "", lineno: int | None = None) -> Dependency | None:
    hashes = re.findall(r"--hash[=\s]+(sha256:[0-9a-fA-F]{64})", line)
    line = re.sub(r"\s--hash[=\s]+\S+", "", line)
    line = line.split(" #", 1)[0].strip()
    if not line or line.startswith("#") or line.startswith("-") and not line.startswith(("-e ", "--editable")):
        return None
    if line.startswith(("-e ", "--editable")):
        url = line.split(None, 1)[1]
        m = re.search(r"#egg=([A-Za-z0-9_.\-]+)", url)
        if not m:
            return None
        return Dependency(canonicalize_name(m.group(1)), m.group(1), url=url, source=source, line=lineno)
    if re.match(r"^(git\+|hg\+|svn\+|https?://|file:)", line):
        m = re.search(r"#egg=([A-Za-z0-9_.\-]+)", line)
        name = m.group(1) if m else line.rsplit("/", 1)[-1]
        return Dependency(canonicalize_name(name), name, url=line, source=source, line=lineno)
    try:
        req = Requirement(line)
    except InvalidRequirement:
        return None
    return Dependency(
        name=canonicalize_name(req.name),
        raw_name=req.name,
        specifier=str(req.specifier),
        pinned_version=_pinned(req),
        hashes=hashes,
        url=req.url,
        source=source,
        line=lineno,
    )


def parse_requirements(path: Path, _seen: set[Path] | None = None) -> list[Dependency]:
    path = Path(path)
    _seen = _seen or set()
    if path.resolve() in _seen or not path.is_file():
        return []
    _seen.add(path.resolve())
    deps: list[Dependency] = []
    text = path.read_text(encoding="utf-8", errors="replace")
    # 줄 이어쓰기(\) 처리
    logical: list[tuple[int, str]] = []
    buf, start = "", 0
    for i, raw in enumerate(text.splitlines(), 1):
        if not buf:
            start = i
        if raw.rstrip().endswith("\\"):
            buf += raw.rstrip()[:-1] + " "
            continue
        logical.append((start, buf + raw))
        buf = ""
    for lineno, line in logical:
        s = line.strip()
        m = re.match(r"^(-r|--requirement|-c|--constraint)\s+(\S+)", s)
        if m:
            inc = (path.parent / m.group(2)).resolve()
            # 기준 디렉터리 밖 참조 방지
            if inc.is_relative_to(path.parent.resolve().parent) or inc.is_relative_to(path.parent.resolve()):
                deps.extend(parse_requirements(inc, _seen))
            continue
        d = parse_requirement_line(s, str(path.name), lineno)
        if d:
            deps.append(d)
    return deps


def parse_pyproject(path: Path) -> list[Dependency]:
    data = tomllib.loads(Path(path).read_text(encoding="utf-8"))
    project = data.get("project", {})
    lines: list[str] = list(project.get("dependencies", []))
    for extra in project.get("optional-dependencies", {}).values():
        lines.extend(extra)
    # poetry
    poetry = data.get("tool", {}).get("poetry", {}).get("dependencies", {})
    for name, spec in poetry.items():
        if name.lower() == "python":
            continue
        ver = spec if isinstance(spec, str) else spec.get("version", "") if isinstance(spec, dict) else ""
        lines.append(name if ver in ("", "*") else f"{name}{_poetry_spec(ver)}")
    out = []
    for ln in lines:
        d = parse_requirement_line(ln, Path(path).name)
        if d:
            out.append(d)
    return out


def _poetry_spec(ver: str) -> str:
    ver = ver.strip()
    if ver.startswith("^"):
        return ">=" + ver[1:]
    if ver.startswith("~"):
        return "~=" + ver[1:]
    if ver[:1].isdigit():
        return "==" + ver
    return ver


def discover_dependencies(root: Path) -> list[Dependency]:
    root = Path(root)
    deps: list[Dependency] = []
    seen: set[Path] = set()
    candidates = sorted(root.glob("requirements*.txt")) + sorted(root.glob("requirements/*.txt"))
    for p in candidates:
        deps.extend(parse_requirements(p, seen))
    if (root / "pyproject.toml").is_file():
        try:
            deps.extend(parse_pyproject(root / "pyproject.toml"))
        except (tomllib.TOMLDecodeError, OSError):
            pass
    return deps
