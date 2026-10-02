"""F5. AI 모델 파일 스캔 : ProtectAI ModelScan 연동 (설치되어 있으면 실행).

자체 정적 스캐너(scan/modelscan.py)가 찾은 모델 파일만 ModelScan 으로 다시 검사한다 (저장소 전체를 훑지 않음).
같은 파일에 자체 스캐너 결과가 이미 있으면 그쪽을 남기고, ModelScan 만 찾은 문제는 추가한다.
"""

from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path
from typing import Any

from trustchain.core.findings import Finding, Severity
from trustchain.secure_coding.runner import _run_tool

__all__ = ["merge_model_findings", "parse_modelscan", "run_modelscan"]


def parse_modelscan(data: Any, rel_dir: str) -> list[Finding]:
    """ModelScan JSON 리포트 → Finding. source 는 스캔 대상 기준 상대 경로이므로 rel_dir 을 앞에 붙인다."""
    if not isinstance(data, dict):
        return []
    out = []
    for it in data.get("issues") or []:
        if not isinstance(it, dict) or not it.get("source"):
            continue
        scanner = str(it.get("scanner") or "unknown").split(".")[-1]
        src = it["source"].replace("\\", "/")
        path = src if not rel_dir or src.startswith(rel_dir + "/") else f"{rel_dir}/{src}"
        out.append(Finding(
            rule_id=f"MODELSCAN-{scanner}", title="ModelScan 이 위험을 찾은 모델 파일",
            severity=Severity.parse(it.get("severity"), Severity.HIGH), category="model", file=path,
            message=str(it.get("description") or ""), cwe="CWE-502", tool="modelscan",
            fix="출처를 확인할 수 없는 모델은 사용하지 마세요. safetensors/.keras(safe_mode) 형식으로 교체하세요.",
            extra={"operator": it.get("operator"), "module": it.get("module")},
        ))
    return out


def run_modelscan(root: Path, model_paths: list[str]) -> tuple[list[Finding], str]:
    """model_paths : 프로젝트 루트 기준 상대 경로. 상태 ok / missing / failed / no-models."""
    if not model_paths:
        return [], "no-models"
    if not shutil.which("modelscan"):
        return [], "missing"
    out, ok = [], False
    with tempfile.TemporaryDirectory() as td:
        for i, rp in enumerate(model_paths):
            report = Path(td) / f"r{i}.json"
            _run_tool(["modelscan", "-p", str(root / rp), "-r", "json", "-o", str(report)], timeout=600)
            try:
                data = json.loads(report.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            ok = True
            # 단일 파일을 스캔하면 source 는 파일 이름이므로, 파일이 있는 디렉터리를 붙인다
            parent = str(Path(rp).parent).replace("\\", "/")
            out += parse_modelscan(data, "" if parent == "." else parent)
    return out, "ok" if ok else "failed"


def merge_model_findings(existing: list[Finding], new: list[Finding]) -> list[Finding]:
    """자체 스캐너가 같은 파일을 같거나 더 높은 심각도로 이미 보고했으면 ModelScan 결과는 뺀다 (중복 보고 방지).

    자체 스캐너가 낮은 심각도(예: pickle 형식 권고)만 냈는데 ModelScan 이 더 심각한 문제를 찾으면 추가한다.
    """
    worst: dict[str | None, int] = {}
    for f in existing:
        if f.category == "model":
            worst[f.file] = max(worst.get(f.file, -1), f.severity.rank)
    return [f for f in new if worst.get(f.file, -1) < f.severity.rank]
