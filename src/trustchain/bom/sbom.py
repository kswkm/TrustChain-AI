"""F6. SBOM 생성 (CycloneDX 1.6 JSON).

Syft 가 설치되어 있으면 Syft 로 디렉터리/이미지를 분석하고, 없으면 의존성 파일과
현재 파이썬 환경에서 자체 생성한다.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess  # nosec - 고정 인자 리스트
import uuid
from datetime import datetime, timezone
from importlib import metadata
from pathlib import Path
from typing import Any
from urllib.parse import unquote

from packaging.utils import canonicalize_name

from trustchain import __version__
from trustchain.packages.requirements import discover_dependencies

SPEC = "1.6"
PURL_ECOSYSTEM = {
    "pypi": "PyPI", "npm": "npm", "deb": "Debian", "apk": "Alpine", "golang": "Go", "maven": "Maven",
    "cargo": "crates.io", "gem": "RubyGems", "nuget": "NuGet", "rpm": "Red Hat", "composer": "Packagist",
}


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def empty_bom(name: str, version: str = "0.0.0") -> dict[str, Any]:
    return {
        "bomFormat": "CycloneDX",
        "specVersion": SPEC,
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": _now(),
            "tools": {"components": [{"type": "application", "name": "trustchain-ai", "version": __version__}]},
            "component": {"type": "application", "name": name, "version": version, "bom-ref": f"app:{name}"},
        },
        "components": [],
    }


def pypi_component(name: str, version: str | None, hashes: list[str] | None = None) -> dict[str, Any]:
    n = canonicalize_name(name)
    purl = f"pkg:pypi/{n}@{version}" if version else f"pkg:pypi/{n}"
    c: dict[str, Any] = {"type": "library", "bom-ref": purl, "name": n, "purl": purl}
    if version:
        c["version"] = version
    if hashes:
        c["hashes"] = [{"alg": "SHA-256", "content": h.split(":", 1)[1]} for h in hashes if h.startswith("sha256:")]
    return c


def sbom_from_project(root: Path, name: str, version: str = "0.0.0", from_env: bool = False) -> dict[str, Any]:
    bom = empty_bom(name, version)
    seen: dict[str, dict[str, Any]] = {}
    for d in discover_dependencies(root):
        if d.name not in seen:
            seen[d.name] = pypi_component(d.raw_name, d.pinned_version, d.hashes)
    if from_env:
        # 실제 설치된 버전(간접 의존성 포함)으로 보강
        for dist in metadata.distributions():
            n = canonicalize_name(dist.metadata["Name"] or "")
            if not n:
                continue
            comp = seen.get(n)
            if comp is None or "version" not in comp:
                seen[n] = pypi_component(n, dist.version)
    bom["components"] = sorted(seen.values(), key=lambda c: c["name"])
    return bom


def run_syft(target: str, timeout: int = 900) -> dict[str, Any] | None:
    exe = shutil.which("syft")
    if not exe or not re.match(r"^[A-Za-z0-9._\-/:@\\]+$", target):
        return None
    try:
        r = subprocess.run([exe, "scan", target, "-o", "cyclonedx-json", "-q"],  # nosec
                           capture_output=True, text=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if r.returncode != 0:
        return None
    try:
        return json.loads(r.stdout)
    except ValueError:
        return None


def generate_sbom(root: Path, name: str, version: str = "0.0.0", target: str | None = None,
                  use_syft: bool = True, from_env: bool = False) -> dict[str, Any]:
    if use_syft:
        bom = run_syft(target or str(root))
        if bom:
            bom.setdefault("metadata", {}).setdefault("component", {"type": "application", "name": name,
                                                                    "version": version})
            return bom
    return sbom_from_project(root, name, version, from_env)


def parse_purl(purl: str) -> dict[str, str | None]:
    """pkg:type/namespace/name@version?qualifiers#subpath → 구성요소."""
    m = re.match(r"^pkg:([a-zA-Z0-9.+\-]+)/([^@?#]+)(?:@([^?#]+))?", purl or "")
    if not m:
        return {"type": None, "namespace": None, "name": None, "version": None}
    ptype, path, ver = m.group(1).lower(), unquote(m.group(2)), unquote(m.group(3)) if m.group(3) else None
    ns, _, nm = path.rpartition("/")
    return {"type": ptype, "namespace": ns or None, "name": nm, "version": ver}


def components_from_sbom(bom: dict[str, Any]) -> list[dict[str, Any]]:
    """SBOM → 인벤토리 저장/취약점 매칭용 평탄화 목록 (중첩 components 포함)."""
    out: list[dict[str, Any]] = []

    def walk(items: list[dict[str, Any]]) -> None:
        for c in items or []:
            purl = c.get("purl") or ""
            p = parse_purl(purl)
            eco = PURL_ECOSYSTEM.get(p["type"] or "", p["type"])
            if p["type"] == "deb" and p["namespace"] == "ubuntu":
                eco = "Ubuntu"
            name = p["name"] or c.get("name")
            if p["type"] == "maven" and p["namespace"]:
                name = f"{p['namespace']}:{p['name']}"
            out.append({
                "name": name, "version": c.get("version") or p["version"], "purl": purl or None,
                "ecosystem": eco, "type": c.get("type", "library"),
                "sha256": next((h["content"] for h in c.get("hashes", []) if h.get("alg") == "SHA-256"), None),
            })
            walk(c.get("components", []))

    walk(bom.get("components", []))
    return out


def write_bom(bom: dict[str, Any], path: Path) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps(bom, ensure_ascii=False, indent=2), encoding="utf-8")
