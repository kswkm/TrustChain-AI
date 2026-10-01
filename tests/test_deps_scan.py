from __future__ import annotations

from pathlib import Path

from trustchain.core.findings import Finding, Severity
from trustchain.packages.checker import PackageVerdict, verdict_findings
from trustchain.packages.osv import Vuln
from trustchain.scan import deps
from trustchain.scan.deps import merge_dependency_findings, parse_osv_scanner, parse_pip_audit

PIP_AUDIT = {"dependencies": [
    {"name": "requests", "version": "2.19.0", "vulns": [
        {"id": "PYSEC-2018-28", "fix_versions": ["2.20.0"], "aliases": ["CVE-2018-18074", "GHSA-x84v-xcm2-53pg"],
         "description": "Requests sends an HTTP Authorization header to an http URI."}]},
    {"name": "six", "version": "1.16.0", "vulns": []},
]}


def osv_scanner_output(root: Path) -> dict:
    return {"results": [{"source": {"path": str(root / "requirements.txt"), "type": "lockfile"}, "packages": [
        {"package": {"name": "pyyaml", "version": "5.3.0", "ecosystem": "PyPI"},
         "vulnerabilities": [
             {"id": "PYSEC-2020-96", "aliases": ["CVE-2020-1747", "GHSA-6757-jp84-gxfx"], "summary": "",
              "details": "Arbitrary code execution via full_load",
              "affected": [{"package": {"name": "pyyaml", "ecosystem": "PyPI"},
                            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "5.3.1"}]}]}]},
             {"id": "GHSA-6757-jp84-gxfx", "aliases": ["CVE-2020-1747", "PYSEC-2020-96"],
              "summary": "Improper Input Validation in PyYAML", "affected": []}],
         "groups": [{"ids": ["PYSEC-2020-96", "GHSA-6757-jp84-gxfx"],
                     "aliases": ["CVE-2020-1747", "GHSA-6757-jp84-gxfx", "PYSEC-2020-96"], "max_severity": "9.8"}]},
    ]}]}


def test_parse_pip_audit():
    out = parse_pip_audit(PIP_AUDIT, "requirements.txt")
    assert len(out) == 1
    f = out[0]
    assert (f.rule_id, f.tool, f.category, f.file) == ("PYSEC-2018-28", "pip-audit", "dependency", "requirements.txt")
    assert f.extra["package"] == "requests" and f.extra["fixed"] == ["2.20.0"]
    assert {"PYSEC-2018-28", "CVE-2018-18074", "GHSA-x84v-xcm2-53pg"} <= set(f.extra["aliases"])
    assert "2.20.0" in f.fix


def test_parse_osv_scanner_one_finding_per_group(tmp_path):
    out = parse_osv_scanner(osv_scanner_output(tmp_path), tmp_path)
    assert len(out) == 1
    f = out[0]
    assert f.severity == Severity.CRITICAL and f.tool == "osv-scanner" and f.file == "requirements.txt"
    assert f.extra["package"] == "pyyaml" and f.extra["fixed"] == ["5.3.1"]
    assert "Improper Input Validation" in f.message
    assert {"CVE-2020-1747", "GHSA-6757-jp84-gxfx", "PYSEC-2020-96"} <= set(f.extra["aliases"])


def _own(pkg: str, vid: str, aliases: list[str]) -> Finding:
    v = PackageVerdict(name=pkg, raw_name=pkg, version="5.3", verdict="정상", source="requirements.txt", line=2)
    v.vulns = [Vuln(id=vid, aliases=aliases, summary="s")]
    return [f for f in verdict_findings(v) if f.category == "dependency"][0]


def test_own_osv_finding_carries_aliases():
    f = _own("pyyaml", "GHSA-6757-jp84-gxfx", ["CVE-2020-1747"])
    assert {"GHSA-6757-jp84-gxfx", "CVE-2020-1747"} <= set(f.extra["aliases"])


def test_merge_drops_alias_duplicates_keeps_new(tmp_path):
    own = [_own("PyYAML", "GHSA-6757-jp84-gxfx", ["CVE-2020-1747"])]
    scanner = parse_osv_scanner(osv_scanner_output(tmp_path), tmp_path)        # 같은 취약점 (별칭 겹침, 버전 표기 다름)
    audit = parse_pip_audit(PIP_AUDIT, "requirements.txt")                      # 새 취약점
    dup_audit = parse_pip_audit(PIP_AUDIT, "requirements.txt")                  # 도구끼리 중복
    merged = merge_dependency_findings(own, scanner + audit + dup_audit)
    assert [f.rule_id for f in merged] == ["PYSEC-2018-28"]


def test_runners_report_missing_tool(tmp_path, monkeypatch):
    (tmp_path / "requirements.txt").write_text("requests==2.19.0\n", encoding="utf-8")
    monkeypatch.setattr(deps.shutil, "which", lambda name: None)
    assert deps.run_pip_audit(tmp_path) == ([], "missing")
    assert deps.run_osv_scanner(tmp_path) == ([], "missing")


def test_run_pip_audit_parses_tool_output(tmp_path, monkeypatch):
    import json

    (tmp_path / "requirements.txt").write_text("requests==2.19.0\n", encoding="utf-8")
    calls = []

    def fake_run(cmd, timeout=300):
        calls.append(cmd)
        return json.dumps(PIP_AUDIT)

    monkeypatch.setattr(deps.shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(deps, "_run_tool", fake_run)
    out, status = deps.run_pip_audit(tmp_path)
    assert [f.rule_id for f in out] == ["PYSEC-2018-28"] and status == "ok"
    assert calls[0][0] == "pip-audit" and "--no-deps" in calls[0] and "--disable-pip" in calls[0]


def test_run_pip_audit_failed_output(tmp_path, monkeypatch):
    (tmp_path / "requirements.txt").write_text("requests>=2\n", encoding="utf-8")   # 버전 미고정 → 도구 오류 출력
    monkeypatch.setattr(deps.shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(deps, "_run_tool", lambda cmd, timeout=300: "ERROR: not pinned")
    assert deps.run_pip_audit(tmp_path) == ([], "failed")


def test_run_osv_scanner_scans_only_requirement_files(tmp_path, monkeypatch):
    import json

    (tmp_path / "requirements.txt").write_text("pyyaml==5.3\n", encoding="utf-8")
    (tmp_path / ".trustchain-src").mkdir()
    (tmp_path / ".trustchain-src" / "requirements.txt").write_text("pyyaml==5.3\n", encoding="utf-8")
    calls = []

    def fake_run(cmd, timeout=300):
        calls.append(cmd)
        return json.dumps(osv_scanner_output(tmp_path))

    monkeypatch.setattr(deps.shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(deps, "_run_tool", fake_run)
    out, status = deps.run_osv_scanner(tmp_path)
    assert status == "ok" and len(out) == 1
    cmd = calls[0]
    assert "-r" not in cmd and cmd.count("-L") == 1 and cmd[cmd.index("-L") + 1].endswith("requirements.txt")
    assert ".trustchain-src" not in " ".join(cmd)


def test_no_requirement_files_means_nothing_to_scan(tmp_path, monkeypatch):
    monkeypatch.setattr(deps.shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(deps, "_run_tool", lambda *a, **k: (_ for _ in ()).throw(AssertionError("called")))
    assert deps.run_osv_scanner(tmp_path) == ([], "no-requirements")
    assert deps.run_pip_audit(tmp_path) == ([], "no-requirements")


def test_parsers_tolerate_unexpected_shapes(tmp_path):
    assert parse_pip_audit([{"name": "x"}], "r.txt") == []                     # pip-audit 1.x 목록 형식
    assert parse_pip_audit({"dependencies": [{"version": "1"}]}, "r.txt") == []  # 이름 없음
    assert parse_osv_scanner({"results": [{"packages": [{"groups": [{}]}]}]}, tmp_path) == []
    assert parse_osv_scanner(["x"], tmp_path) == []


def test_dependency_scanners_offline_and_status(tmp_path, monkeypatch):
    (tmp_path / "requirements.txt").write_text("requests==2.19.0\n", encoding="utf-8")
    monkeypatch.setattr(deps, "_run_tool", lambda *a, **k: (_ for _ in ()).throw(AssertionError("network")))
    out, status = deps.run_dependency_scanners(tmp_path, offline=True)
    assert out == [] and status == {"osv-scanner": "offline", "pip-audit": "offline"}


def test_gate_runs_dependency_scanners_only_when_requested(cfg, fake_pypi, monkeypatch):
    from trustchain.packages.checker import PackageChecker
    from trustchain.scan.gate import run_gate

    (cfg.root / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")
    monkeypatch.setattr(deps, "run_dependency_scanners", lambda root, offline=False: (
        parse_pip_audit(PIP_AUDIT, "requirements.txt"), {"osv-scanner": "missing", "pip-audit": "ok"}))
    out = run_gate(cfg, stages={"packages"}, checker=PackageChecker(cfg, fake_pypi), dependency_scanners=True)
    assert "PYSEC-2018-28" in {f.rule_id for f in out.report.findings}
    assert out.report.meta["dependency_scanners"] == {"osv-scanner": "missing", "pip-audit": "ok"}
    out = run_gate(cfg, stages={"packages"}, checker=PackageChecker(cfg, fake_pypi))       # 기본값 : 커밋 전 점검에선 실행 안 함
    assert "PYSEC-2018-28" not in {f.rule_id for f in out.report.findings}
    assert "dependency_scanners" not in out.report.meta
