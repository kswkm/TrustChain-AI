"""F5. 의존성 취약점 스캔 : pip-audit · OSV-Scanner 연동 (설치되어 있으면 실행).

자체 OSV 조회(F2·F4)와 같은 취약점은 (패키지, 취약점 ID·별칭 중 하나라도 일치) 기준으로 한 건만 남긴다.
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

__all__ = ["merge_dependency_findings", "parse_osv_scanner", "parse_pip_audit", "run_osv_scanner", "run_pip_audit",
           "shutil"]


def _fix_text(pkg: str, fixed: list[str]) -> str:
    return f"{pkg} → {fixed[0]} 이상으로 업그레이드" if fixed else "패치 버전이 없습니다. 대체 패키지나 완화 조치를 검토하세요."


def parse_pip_audit(data: dict[str, Any], source: str) -> list[Finding]:
    out = []
    for dep in data.get("dependencies") or []:
        for v in dep.get("vulns") or []:
            fixed = list(v.get("fix_versions") or [])
            out.append(Finding(
                rule_id=v["id"], title=f"취약한 의존성 {dep['name']}=={dep.get('version')}",
                # pip-audit 는 심각도를 주지 않는다 : 자체 OSV 조회에 같은 취약점이 있으면 그쪽(심각도 포함)이 남는다
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


def parse_osv_scanner(data: dict[str, Any], root: Path) -> list[Finding]:
    out = []
    for res in data.get("results") or []:
        source = rel(Path((res.get("source") or {}).get("path", "")), root)
        for p in res.get("packages") or []:
            pkg = p.get("package") or {}
            vulns = {v["id"]: v for v in p.get("vulnerabilities") or []}
            for g in p.get("groups") or []:
                ids = list(g.get("ids") or [])
                group_vulns = [vulns[i] for i in ids if i in vulns]
                summary = next((v.get("summary") for v in group_vulns if v.get("summary")), "") or next(
                    (v.get("details", "")[:300] for v in group_vulns if v.get("details")), "")
                fixed = next((f for f in map(_fixed_versions, group_vulns) if f), [])
                try:
                    score = float(g.get("max_severity") or "")
                except ValueError:
                    score = None
                out.append(Finding(
                    rule_id=ids[0] if ids else "OSV-UNKNOWN", title=f"취약한 의존성 {pkg.get('name')}=={pkg.get('version')}",
                    severity=severity_from_score(score), category="dependency", file=source,
                    message=f"{', '.join(ids)} {summary}".strip(), fix=_fix_text(pkg.get("name", ""), fixed),
                    tool="osv-scanner",
                    extra={"package": pkg.get("name"), "version": pkg.get("version"), "fixed": fixed, "cvss": score,
                           "aliases": sorted({*ids, *(g.get("aliases") or [])})},
                ))
    return out


def _ids(f: Finding) -> set[str]:
    return {f.rule_id, *(a for a in f.extra.get("aliases") or [] if a)}


def merge_dependency_findings(existing: list[Finding], new: list[Finding]) -> list[Finding]:
    """existing 과 (패키지, ID·별칭) 이 겹치지 않는 new 만 돌려준다. new 안의 중복도 한 건만 남긴다."""
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


def run_pip_audit(root: Path) -> list[Finding]:
    """고정 버전(==) requirements 를 설치 없이 감사한다 (--no-deps --disable-pip). 도구가 없거나 실패하면 빈 결과."""
    if not shutil.which("pip-audit"):
        return []
    out = []
    for req in _requirement_files(root):
        stdout = _run_tool(["pip-audit", "-r", str(req), "--no-deps", "--disable-pip", "-f", "json",
                            "--progress-spinner", "off"])
        try:
            data = json.loads(stdout or "")
        except ValueError:
            continue  # 버전 미고정 등으로 감사할 수 없는 파일
        out += parse_pip_audit(data, rel(req, root))
    return out


def run_osv_scanner(root: Path) -> list[Finding]:
    if not shutil.which("osv-scanner"):
        return []
    stdout = _run_tool(["osv-scanner", "scan", "source", "--format", "json", "-r", str(root)], timeout=600)
    try:
        data = json.loads(stdout or "")
    except ValueError:
        return []
    return parse_osv_scanner(data, root)
