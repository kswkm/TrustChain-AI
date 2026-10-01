"""F5. 의존성 취약점 스캔 : pip-audit · OSV-Scanner 연동 (설치되어 있으면 실행).

- 대상은 프로젝트 루트의 requirements 파일뿐이다 (저장소 전체를 훑지 않아 테스트 픽스처·체크아웃한 다른 저장소를 건드리지 않음).
- 자체 OSV 조회(F2·F4)와 같은 취약점은 (패키지, 취약점 ID·별칭 중 하나라도 일치) 기준으로 한 건만 남긴다.
- 도구별 실행 결과(ok / missing / failed / offline / no-requirements)를 게이트 리포트에 남긴다.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

from packaging.utils import canonicalize_name

from trustchain.core.files import rel
from trustchain.core.findings import Finding, Severity
from trustchain.packages.osv import severity_from_score
from trustchain.secure_coding.runner import _run_tool

__all__ = ["merge_dependency_findings", "parse_osv_scanner", "parse_pip_audit", "run_dependency_scanners",
           "run_osv_scanner", "run_pip_audit"]


def _fix_text(pkg: str, fixed: list[str]) -> str:
    return f"{pkg} → {fixed[0]} 이상으로 업그레이드" if fixed else "패치 버전이 없습니다. 대체 패키지나 완화 조치를 검토하세요."


def parse_pip_audit(data: Any, source: str) -> list[Finding]:
    """pip-audit 2.x JSON ({"dependencies": [...]}). 예상과 다른 형식은 무시한다."""
    if not isinstance(data, dict):
        return []
    out = []
    for dep in data.get("dependencies") or []:
        if not isinstance(dep, dict) or not dep.get("name"):
            continue
        for v in dep.get("vulns") or []:
            if not isinstance(v, dict) or not v.get("id"):
                continue
            fixed = list(v.get("fix_versions") or [])
            out.append(Finding(
                rule_id=v["id"], title=f"취약한 의존성 {dep['name']}=={dep.get('version')}",
                # pip-audit 는 심각도를 주지 않는다 : 자체 OSV 조회·OSV-Scanner 에 같은 취약점이 있으면 그쪽(심각도 포함)이 남는다
                severity=Severity.MEDIUM, category="dependency", file=source,
                message=f"{v['id']} {(v.get('description') or '').strip()[:300]} (pip-audit, 심각도 정보 없음)".strip(),
                fix=_fix_text(dep["name"], fixed), tool="pip-audit",
                extra={"package": dep["name"], "version": dep.get("version"), "fixed": fixed,
                       "aliases": [v["id"], *(v.get("aliases") or [])]},
            ))
    return out


def _fixed_versions(vuln: dict[str, Any]) -> list[str]:
    out: list[str] = []
    for a in vuln.get("affected") or []:
        for r in a.get("ranges") or []:
            out += [e["fixed"] for e in r.get("events") or [] if "fixed" in e and e["fixed"] not in out]
    return out


def parse_osv_scanner(data: Any, root: Path) -> list[Finding]:
    """osv-scanner v2 JSON. 그룹(같은 취약점의 별칭 묶음)마다 한 건. 예상과 다른 형식은 무시한다."""
    if not isinstance(data, dict):
        return []
    out = []
    for res in data.get("results") or []:
        if not isinstance(res, dict):
            continue
        source = rel(Path((res.get("source") or {}).get("path", "")), root)
        for p in res.get("packages") or []:
            pkg = (p or {}).get("package") or {}
            if not pkg.get("name"):
                continue
            vulns = {v["id"]: v for v in p.get("vulnerabilities") or [] if isinstance(v, dict) and v.get("id")}
            for g in p.get("groups") or []:
                ids = list((g or {}).get("ids") or [])
                if not ids:
                    continue
                group_vulns = [vulns[i] for i in ids if i in vulns]
                summary = next((v.get("summary") for v in group_vulns if v.get("summary")), "") or next(
                    (v.get("details", "")[:300] for v in group_vulns if v.get("details")), "")
                fixed = next((f for f in map(_fixed_versions, group_vulns) if f), [])
                try:
                    score = float(g.get("max_severity") or "")
                except ValueError:
                    score = None
                out.append(Finding(
                    rule_id=ids[0], title=f"취약한 의존성 {pkg['name']}=={pkg.get('version')}",
                    severity=severity_from_score(score), category="dependency", file=source,
                    message=f"{', '.join(ids)} {summary}".strip(), fix=_fix_text(pkg["name"], fixed),
                    tool="osv-scanner",
                    extra={"package": pkg["name"], "version": pkg.get("version"), "fixed": fixed, "cvss": score,
                           "aliases": sorted({*ids, *(g.get("aliases") or [])})},
                ))
    return out


def _ids(f: Finding) -> set[str]:
    return {f.rule_id, *(a for a in f.extra.get("aliases") or [] if a)}


def merge_dependency_findings(existing: list[Finding], new: list[Finding]) -> list[Finding]:
    """existing 과 (패키지, ID·별칭) 이 겹치지 않는 new 만 돌려준다. new 안의 중복도 한 건만 남긴다.

    도구마다 버전 표기가 다를 수 있어(5.3 / 5.3.0) 버전은 비교하지 않는다.
    """
    seen: dict[str, set[str]] = {}
    for f in existing:
        if f.category == "dependency" and f.extra.get("package"):
            seen.setdefault(canonicalize_name(f.extra["package"]), set()).update(_ids(f))
    out = []
    for f in new:
        pkg = canonicalize_name(f.extra.get("package") or "")
        ids = _ids(f)
        if seen.get(pkg, set()) & ids:
            continue
        seen.setdefault(pkg, set()).update(ids)
        out.append(f)
    return out


def _requirement_files(root: Path) -> list[Path]:
    return sorted(root.glob("requirements*.txt")) + sorted(root.glob("requirements/*.txt"))


def _load_json(stdout: str | None) -> Any:
    try:
        return json.loads(stdout or "")
    except ValueError:
        return None


def run_pip_audit(root: Path) -> tuple[list[Finding], str]:
    """고정 버전(==) requirements 를 설치 없이 감사한다 (--no-deps --disable-pip)."""
    reqs = _requirement_files(root)
    if not reqs:
        return [], "no-requirements"
    if not shutil.which("pip-audit"):
        return [], "missing"
    out, ok = [], False
    for req in reqs:
        data = _load_json(_run_tool(["pip-audit", "-r", str(req), "--no-deps", "--disable-pip", "-f", "json",
                                     "--progress-spinner", "off"]))
        if isinstance(data, dict):
            ok = True
            out += parse_pip_audit(data, rel(req, root))
        # 그 밖(버전 미고정 등으로 감사할 수 없는 파일)은 건너뛴다
    return out, "ok" if ok else "failed"


def run_osv_scanner(root: Path) -> tuple[list[Finding], str]:
    reqs = _requirement_files(root)
    if not reqs:
        return [], "no-requirements"
    if not shutil.which("osv-scanner"):
        return [], "missing"
    cmd = ["osv-scanner", "scan", "source", "--format", "json"]
    for req in reqs:
        cmd += ["-L", str(req)]
    data = _load_json(_run_tool(cmd, timeout=600))
    if not isinstance(data, dict):
        return [], "failed"
    return parse_osv_scanner(data, root), "ok"


def run_dependency_scanners(root: Path, offline: bool = False) -> tuple[list[Finding], dict[str, str]]:
    """OSV-Scanner → pip-audit 순서(심각도 정보가 있는 쪽 우선). 오프라인이면 네트워크가 필요한 두 도구를 실행하지 않는다."""
    if offline:
        return [], {"osv-scanner": "offline", "pip-audit": "offline"}
    osv, s1 = run_osv_scanner(root)
    pa, s2 = run_pip_audit(root)
    return osv + pa, {"osv-scanner": s1, "pip-audit": s2}
