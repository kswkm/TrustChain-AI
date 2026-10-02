from __future__ import annotations

import json

from trustchain.core.config import Config
from trustchain.core.findings import Severity
from trustchain.iac import k8s
from trustchain.iac.k8s import parse_checkov

# Checkov 3.3.22 실제 출력 (deploy/k8s + 열린 보안 그룹 Terraform 예시, -o json --compact) 에서 발췌
REAL = [
    {"check_type": "kubernetes", "results": {"failed_checks": [
        {"check_id": "CKV_K8S_8", "check_name": "Liveness Probe Should be Configured", "severity": None,
         "file_path": "/deploy/k8s/base/mnist-api.yaml", "file_line_range": [7, 33],
         "resource": "Deployment.app.mnist-api", "guideline": "https://docs.prismacloud.io/x"}]}},
    {"check_type": "terraform", "results": {"failed_checks": [
        {"check_id": "CKV_AWS_24", "check_name": "Ensure no security groups allow ingress from 0.0.0.0:0 to port 22",
         "severity": None, "file_path": "/tf/main.tf", "file_line_range": [1, 9],
         "resource": "aws_security_group.open", "guideline": None}]}},
]


def test_parse_checkov_real_output():
    out = parse_checkov(REAL)
    assert [(f.rule_id, f.file, f.line, f.category, f.tool) for f in out] == [
        ("CKV_K8S_8", "deploy/k8s/base/mnist-api.yaml", 7, "iac", "checkov"),
        ("CKV_AWS_24", "tf/main.tf", 1, "iac", "checkov"),
    ]
    assert out[1].severity == Severity.MEDIUM          # 무료 Checkov 는 심각도를 주지 않음 → MEDIUM 으로 기록
    assert "aws_security_group.open" in out[1].message


def test_parse_checkov_single_report_and_bad_shapes():
    assert len(parse_checkov(REAL[0])) == 1             # 프레임워크가 하나면 리스트가 아닌 객체
    assert parse_checkov("x") == [] and parse_checkov([{"results": None}]) == []


def test_run_checkov_status_and_excludes(tmp_path, monkeypatch):
    monkeypatch.setattr(k8s.shutil, "which", lambda name: None)
    assert k8s.run_checkov(tmp_path) == ([], "missing")
    calls = []

    def fake_run(cmd, timeout=300):
        calls.append(cmd)
        return json.dumps(REAL)

    monkeypatch.setattr(k8s.shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(k8s, "_run_tool", fake_run)
    out, status = k8s.run_checkov(tmp_path, exclude=[".venv", "node_modules"])
    assert status == "ok" and len(out) == 2
    cmd = calls[0]
    assert cmd[cmd.index("--framework") + 1:cmd.index("--framework") + 4] == ["kubernetes", "terraform", "dockerfile"]
    skips = [cmd[i + 1] for i, a in enumerate(cmd) if a == "--skip-path"]
    assert any(r"\.venv" in x for x in skips) and any("node_modules" in x for x in skips)
    monkeypatch.setattr(k8s, "_run_tool", lambda cmd, timeout=300: "not json")
    assert k8s.run_checkov(tmp_path) == ([], "failed")


def test_gate_records_iac_scanner_status(tmp_path, monkeypatch):
    from trustchain.scan.gate import run_gate

    monkeypatch.setattr(k8s, "run_checkov", lambda root, exclude=None: (parse_checkov(REAL), "ok"))
    import trustchain.scan.gate as gate

    monkeypatch.setattr(gate, "run_checkov", lambda root, exclude=None: (parse_checkov(REAL), "ok"))
    out = run_gate(Config(root=tmp_path), stages={"iac"}, external_tools=True)
    assert {"CKV_K8S_8", "CKV_AWS_24"} <= {f.rule_id for f in out.report.findings}
    assert out.report.meta["iac_scanners"] == {"checkov": "ok"}


def test_checkov_skip_paths_are_anchored_directory_patterns(tmp_path, monkeypatch):
    # --skip-path 는 정규식 : 'dist' 가 'distroless/Dockerfile' 까지 건너뛰지 않도록 디렉터리 이름 단위로 고정
    import re

    calls = []
    monkeypatch.setattr(k8s.shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(k8s, "_run_tool", lambda cmd, timeout=300: calls.append(cmd) or "[]")
    k8s.run_checkov(tmp_path, exclude=["dist", ".venv"])
    pats = [calls[0][i + 1] for i, a in enumerate(calls[0]) if a == "--skip-path"]
    for pat, hit, miss in ((pats[0], "dist/app.yaml", "distroless/Dockerfile"), (pats[1], "a/.venv/x.tf", "a/xvenv/x.tf")):
        assert re.search(pat, hit) and not re.search(pat, miss), pat
