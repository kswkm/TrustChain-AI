"""F9. Kubernetes 매니페스트 보안 설정 점검 (자체 룰 + Checkov 연동).

Checkov 가 없는 환경에서도 핵심 항목은 자체 룰로 점검한다.
YAML 파서는 PyYAML(safe_load)을 쓰되, 없으면 JSON 매니페스트만 처리한다.
"""

from __future__ import annotations

import json
import shutil
import subprocess  # nosec - 고정 인자 리스트
from pathlib import Path
from typing import Any, Iterator

from trustchain.core.files import iter_files, read_text, rel
from trustchain.core.findings import Finding, Severity

WORKLOAD_KINDS = {"Pod", "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "CronJob"}


def _load_docs(text: str, suffix: str) -> list[Any]:
    if suffix == ".json":
        try:
            return [json.loads(text)]
        except ValueError:
            return []
    try:
        import yaml
    except ImportError:
        return []
    try:
        return [d for d in yaml.safe_load_all(text) if d]
    except yaml.YAMLError:
        return []


def _pod_spec(doc: dict[str, Any]) -> dict[str, Any] | None:
    kind = doc.get("kind")
    spec = doc.get("spec") or {}
    if kind == "Pod":
        return spec
    if kind == "CronJob":
        return (((spec.get("jobTemplate") or {}).get("spec") or {}).get("template") or {}).get("spec")
    if kind in WORKLOAD_KINDS:
        return (spec.get("template") or {}).get("spec")
    return None


def _containers(ps: dict[str, Any]) -> Iterator[dict[str, Any]]:
    for key in ("initContainers", "containers"):
        yield from ps.get(key) or []


def check_manifest(doc: dict[str, Any], path: str) -> list[Finding]:
    out: list[Finding] = []
    ps = _pod_spec(doc)
    if not ps:
        return out
    name = f"{doc.get('kind')}/{(doc.get('metadata') or {}).get('name', '?')}"

    def add(rid: str, title: str, sev: Severity, msg: str, fix: str) -> None:
        out.append(Finding(rule_id=rid, title=title, severity=sev, category="iac", file=path,
                           message=f"{name}: {msg}", fix=fix, tool="trustchain-iac"))

    if ps.get("hostNetwork") or ps.get("hostPID") or ps.get("hostIPC"):
        add("TC-K8S-001", "호스트 네임스페이스 공유", Severity.HIGH, "hostNetwork/hostPID/hostIPC 가 활성화되어 있습니다.",
            "호스트 네임스페이스 공유를 제거하세요.")
    for v in ps.get("volumes") or []:
        if "hostPath" in v:
            add("TC-K8S-002", "hostPath 볼륨", Severity.HIGH, f"hostPath 볼륨 '{v.get('name')}' 을 마운트합니다.",
                "emptyDir/PVC 를 사용하세요.")
    if ps.get("automountServiceAccountToken") is not False and not ps.get("serviceAccountName"):
        add("TC-K8S-003", "기본 서비스 계정 토큰 자동 마운트", Severity.LOW,
            "전용 서비스 계정 없이 default 토큰이 마운트됩니다.",
            "serviceAccountName 을 지정하고 필요 없으면 automountServiceAccountToken: false")
    pod_sc = ps.get("securityContext") or {}
    for c in _containers(ps):
        cn = c.get("name", "?")
        img = c.get("image", "")
        sc = c.get("securityContext") or {}
        if "@sha256:" not in img:
            add("TC-K8S-004", "이미지 digest 미지정", Severity.MEDIUM, f"컨테이너 '{cn}' 이미지 '{img}' 가 digest 로 고정되지 않았습니다.",
                "image: ghcr.io/org/app@sha256:<digest> 형식으로 배포하세요 (서명 검증 대상과 일치).")
        if sc.get("privileged"):
            add("TC-K8S-005", "특권 컨테이너", Severity.CRITICAL, f"컨테이너 '{cn}' 가 privileged 로 실행됩니다.",
                "privileged: false")
        if sc.get("allowPrivilegeEscalation", True) is not False:
            add("TC-K8S-006", "권한 상승 허용", Severity.MEDIUM, f"컨테이너 '{cn}' 에 allowPrivilegeEscalation: false 가 없습니다.",
                "securityContext.allowPrivilegeEscalation: false")
        if not (sc.get("runAsNonRoot") or pod_sc.get("runAsNonRoot")):
            add("TC-K8S-007", "root 실행 가능", Severity.MEDIUM, f"컨테이너 '{cn}' 에 runAsNonRoot 가 설정되지 않았습니다.",
                "securityContext.runAsNonRoot: true, runAsUser: 10001")
        if not sc.get("readOnlyRootFilesystem"):
            add("TC-K8S-008", "쓰기 가능한 루트 파일시스템", Severity.LOW, f"컨테이너 '{cn}' 의 루트 파일시스템이 쓰기 가능합니다.",
                "readOnlyRootFilesystem: true 와 필요한 경로만 emptyDir 마운트")
        caps = ((sc.get("capabilities") or {}).get("drop")) or []
        if "ALL" not in caps:
            add("TC-K8S-009", "Linux capability 미제거", Severity.LOW, f"컨테이너 '{cn}' 가 capability 를 drop 하지 않습니다.",
                "capabilities: { drop: [\"ALL\"] }")
        res = c.get("resources") or {}
        if not (res.get("limits") or {}).get("memory"):
            add("TC-K8S-010", "리소스 제한 없음", Severity.LOW, f"컨테이너 '{cn}' 에 메모리 limit 이 없습니다 (자원 고갈).",
                "resources.limits.memory / cpu 지정")
        for e in c.get("env") or []:
            n = str(e.get("name", "")).upper()
            if "value" in e and any(k in n for k in ("PASSWORD", "SECRET", "TOKEN", "API_KEY")):
                add("TC-K8S-011", "매니페스트에 하드코딩된 비밀정보", Severity.HIGH,
                    f"컨테이너 '{cn}' 환경변수 '{e.get('name')}' 에 값이 직접 기록되어 있습니다.",
                    "valueFrom.secretKeyRef 로 Secret 을 참조하세요.")
    return out


def check_k8s(root: Path, exclude: list[str]) -> list[Finding]:
    out: list[Finding] = []
    for p in iter_files(root, (".yaml", ".yml", ".json"), exclude):
        text = read_text(p)
        if not text or "apiVersion" not in text or "kind" not in text:
            continue
        for doc in _load_docs(text, p.suffix.lower()):
            if isinstance(doc, dict):
                out.extend(check_manifest(doc, rel(p, root)))
    return out


def run_checkov(root: Path, timeout: int = 600) -> list[Finding]:
    exe = shutil.which("checkov")
    if not exe:
        return []
    try:
        r = subprocess.run(  # nosec
            [exe, "-d", str(root), "--framework", "kubernetes", "terraform", "dockerfile", "-o", "json", "--quiet",
             "--compact"], capture_output=True, text=True, timeout=timeout, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    try:
        data = json.loads(r.stdout or "[]")
    except ValueError:
        return []
    reports = data if isinstance(data, list) else [data]
    out = []
    for rep in reports:
        for fc in ((rep.get("results") or {}).get("failed_checks")) or []:
            out.append(Finding(
                rule_id=fc.get("check_id", "CKV"), title=fc.get("check_name", ""),
                severity=Severity.parse(fc.get("severity"), Severity.MEDIUM), category="iac",
                file=(fc.get("file_path") or "").lstrip("/"), line=(fc.get("file_line_range") or [None])[0],
                message=f"{fc.get('resource')}: {fc.get('check_name')}", fix=fc.get("guideline"), tool="checkov",
            ))
    return out
