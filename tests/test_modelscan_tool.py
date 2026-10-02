from __future__ import annotations

import json
import pickle
from pathlib import Path

from trustchain.core.config import Config
from trustchain.core.findings import Finding, Severity
from trustchain.scan import external_models as em
from trustchain.scan.external_models import merge_model_findings, parse_modelscan

# ProtectAI ModelScan 0.8.8 의 실제 JSON 출력 (evil.pkl : os.system 호출 pickle)
REPORT = {
    "summary": {"total_issues_by_severity": {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 1}, "total_issues": 1,
                "scanned": {"total_scanned": 2, "scanned_files": ["evil.pkl", "ok.pkl"]}},
    "issues": [{"description": "Use of unsafe operator 'system' from module 'nt'", "operator": "system", "module": "nt",
                "source": "evil.pkl", "scanner": "modelscan.scanners.PickleUnsafeOpScan", "severity": "CRITICAL"}],
    "errors": [],
}


def test_parse_modelscan():
    out = parse_modelscan(REPORT, "models")
    assert len(out) == 1
    f = out[0]
    assert (f.rule_id, f.severity, f.category, f.tool) == ("MODELSCAN-PickleUnsafeOpScan", Severity.CRITICAL, "model", "modelscan")
    assert f.file == "models/evil.pkl" and "system" in f.message


def test_parse_modelscan_tolerates_bad_shapes():
    assert parse_modelscan([], "m") == [] and parse_modelscan({"issues": [{}]}, "m") == []


def test_run_modelscan_status(tmp_path, monkeypatch):
    assert em.run_modelscan(tmp_path, []) == ([], "no-models")
    monkeypatch.setattr(em.shutil, "which", lambda name: None)
    assert em.run_modelscan(tmp_path, ["m/evil.pkl"]) == ([], "missing")


def test_run_modelscan_invokes_tool_per_model_file(tmp_path, monkeypatch):
    calls = []

    def fake_run(cmd, timeout=300):
        calls.append(cmd)
        Path(cmd[cmd.index("-o") + 1]).write_text(json.dumps(REPORT), encoding="utf-8")
        return ""

    monkeypatch.setattr(em.shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(em, "_run_tool", fake_run)
    out, status = em.run_modelscan(tmp_path, ["models/evil.pkl"])
    assert status == "ok" and [f.file for f in out] == ["models/evil.pkl"]
    assert calls[0][:3] == ["modelscan", "-p", str(tmp_path / "models" / "evil.pkl")] and "json" in calls[0]


def test_merge_keeps_own_finding_for_same_file():
    own = [Finding("TC-MODEL-001", "t", Severity.CRITICAL, "m", category="model", file="models/evil.pkl")]
    tool = parse_modelscan(REPORT, "models")
    other = Finding("MODELSCAN-X", "t", Severity.HIGH, "m", category="model", file="models/other.h5", tool="modelscan")
    assert merge_model_findings(own, tool + [other]) == [other]


def test_gate_runs_modelscan_with_external_tools(tmp_path, monkeypatch):
    from trustchain.scan.gate import run_gate

    (tmp_path / "models").mkdir()
    with open(tmp_path / "models" / "weights.pkl", "wb") as f:
        pickle.dump({"w": [1, 2]}, f)
    seen = []

    def fake(root, paths):
        seen.append(paths)
        return [Finding("MODELSCAN-H5LambdaDetectScan", "t", Severity.HIGH, "m", category="model",
                        file="models/weights.pkl", tool="modelscan")], "ok"

    monkeypatch.setattr(em, "run_modelscan", fake)
    cfg = Config(root=tmp_path)
    out = run_gate(cfg, stages={"models"}, external_tools=True)
    assert seen == [["models/weights.pkl"]]
    assert "MODELSCAN-H5LambdaDetectScan" in {f.rule_id for f in out.report.findings}
    assert out.report.meta["model_scanners"] == {"modelscan": "ok"}
    out = run_gate(cfg, stages={"models"}, external_tools=False)
    assert "model_scanners" not in out.report.meta
