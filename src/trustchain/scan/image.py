"""F5. 컨테이너 이미지 취약점 스캔 (Trivy 연동) 과 Dockerfile 점검."""

from __future__ import annotations

import json
import re
import shutil
import subprocess  # nosec - 고정 인자 리스트
from pathlib import Path
from typing import Any

from trustchain.core.files import iter_files, read_text, rel
from trustchain.core.findings import Finding, Severity

_IMAGE_REF = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._\-/:@]{0,254}$")


def parse_trivy(data: dict[str, Any], target: str) -> list[Finding]:
    out: list[Finding] = []
    os_info = (data.get("Metadata") or {}).get("OS") or {}
    if os_info.get("EOSL"):
        # 지원 종료 OS 의 취약점은 앞으로도 패치되지 않으므로 '패치 없음 무시' 정책과 무관하게 차단 대상이다
        name = f"{os_info.get('Family', '')} {os_info.get('Name', '')}".strip()
        out.append(Finding(
            rule_id="TC-IMG-006", title="지원이 끝난 OS 베이스 이미지", severity=Severity.CRITICAL, category="image",
            file=target, message=f"{name} 은(는) 보안 지원이 종료되어 새 취약점이 패치되지 않습니다.", cwe="CWE-1104",
            fix="지원 중인 최신 OS 기반 이미지(예: python:3.11-slim 최신 digest)로 교체하세요.", tool="trivy",
            extra={"os": name},
        ))
    for res in data.get("Results", []) or []:
        for v in res.get("Vulnerabilities", []) or []:
            sev = Severity.parse(v.get("Severity"))
            fixed = v.get("FixedVersion")
            out.append(Finding(
                rule_id=v.get("VulnerabilityID", "UNKNOWN"),
                title=f"이미지 취약 패키지 {v.get('PkgName')} {v.get('InstalledVersion')}",
                severity=sev, category="image", file=f"{target}:{res.get('Target', '')}",
                message=(v.get("Title") or v.get("Description") or "")[:300],
                fix=f"{v.get('PkgName')} 를 {fixed} 이상으로 업데이트하거나 최신 패치 베이스 이미지를 사용하세요."
                if fixed else "패치가 없습니다. 더 작은(distroless/slim) 베이스 이미지로 교체를 검토하세요.",
                cwe=(v.get("CweIDs") or [None])[0], tool="trivy",
                extra={"pkg": v.get("PkgName"), "installed": v.get("InstalledVersion"), "fixed": fixed,
                       "class": res.get("Class"), "unfixed": not fixed},
            ))
    return out


def scan_image(image: str, timeout: int = 900) -> tuple[list[Finding], str | None]:
    """trivy 로 이미지 스캔. (결과, 오류메시지)."""
    if not _IMAGE_REF.match(image):
        return [], "잘못된 이미지 참조 형식"
    exe = shutil.which("trivy")
    if not exe:
        return [], "trivy 가 설치되어 있지 않습니다"
    try:
        r = subprocess.run(  # nosec - 인자 리스트, 셸 미사용
            [exe, "image", "--quiet", "--format", "json", "--scanners", "vuln", image],
            capture_output=True, text=True, timeout=timeout, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as e:
        return [], f"trivy 실행 실패: {e.__class__.__name__}"
    if r.returncode != 0:
        return [], "trivy 스캔 실패"
    try:
        return parse_trivy(json.loads(r.stdout), image), None
    except ValueError:
        return [], "trivy 출력 파싱 실패"


def check_dockerfiles(root: Path, exclude: list[str]) -> list[Finding]:
    out: list[Finding] = []
    for p in iter_files(root, None, exclude):
        if not (p.name == "Dockerfile" or p.name.startswith("Dockerfile.") or p.suffix == ".dockerfile"):
            continue
        text = read_text(p) or ""
        rp = rel(p, root)
        has_user = False
        # 멀티 스테이지 빌드의 스테이지 별칭(FROM x AS builder)은 외부 이미지가 아니다
        stages = {m.lower() for m in re.findall(r"(?im)^FROM\s+\S+(?:\s+\S+)?\s+AS\s+(\S+)", text)}
        for i, line in enumerate(text.splitlines(), 1):
            s = line.strip()
            m = re.match(r"(?i)^FROM\s+(--platform=\S+\s+)?(\S+)", s)
            if m and m.group(2).lower() not in stages | {"scratch"}:
                img = m.group(2)
                if "@sha256:" not in img:
                    out.append(Finding(
                        rule_id="TC-IMG-001", title="베이스 이미지 digest 미고정", severity=Severity.MEDIUM,
                        category="image", file=rp, line=i,
                        message=f"'{img}' 가 태그로만 지정되어 있어 같은 태그의 다른(변조된) 이미지가 사용될 수 있습니다.",
                        fix=f"FROM {img.split('@')[0]}@sha256:<digest> 형식으로 고정하세요 (docker buildx imagetools inspect).",
                    ))
                if img.endswith(":latest") or (":" not in img.split("/")[-1] and "@" not in img):
                    out.append(Finding(
                        rule_id="TC-IMG-002", title="latest 태그 사용", severity=Severity.LOW, category="image",
                        file=rp, line=i, message=f"'{img}' 는 재현 불가능한 latest 태그를 사용합니다.",
                        fix="명시적 버전 태그와 digest 를 사용하세요.",
                    ))
            if re.match(r"(?i)^USER\s+(?!root\b|0\b)\S+", s):
                has_user = True
            if re.search(r"(?i)(curl|wget)\s[^|]*\|\s*(ba)?sh", s):
                out.append(Finding(
                    rule_id="TC-IMG-003", title="무결성 검사 없는 코드 다운로드", severity=Severity.HIGH, category="image",
                    file=rp, line=i, message="원격 스크립트를 검증 없이 셸로 실행합니다.", cwe="CWE-494",
                    kisa="보안기능 - 무결성 검사 없는 코드 다운로드",
                    fix="파일을 내려받은 뒤 SHA-256 체크섬/서명을 검증하고 실행하세요.",
                ))
            if re.search(r"(?i)^(ENV|ARG)\s+\S*(PASSWORD|SECRET|TOKEN|API_KEY)\S*[=\s]+\S+", s):
                out.append(Finding(
                    rule_id="TC-IMG-004", title="이미지에 포함된 비밀정보", severity=Severity.HIGH, category="image",
                    file=rp, line=i, message="ENV/ARG 로 비밀정보가 이미지 레이어에 기록됩니다.", cwe="CWE-798",
                    fix="BuildKit secret mount(--mount=type=secret) 또는 런타임 시크릿을 사용하세요.",
                ))
        if text and not has_user:
            out.append(Finding(
                rule_id="TC-IMG-005", title="root 로 실행되는 컨테이너", severity=Severity.MEDIUM, category="image",
                file=rp, message="USER 지시어가 없어 컨테이너가 root 로 실행됩니다.", cwe="CWE-250",
                fix="RUN useradd -u 10001 app && USER 10001",
            ))
    return out
