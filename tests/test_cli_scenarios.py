import json
import subprocess
import sys
from pathlib import Path

from trustchain.cli import main

ROOT = Path(__file__).resolve().parents[1]


def test_cli_check_json_and_exit_code(tmp_path, capsys):
    (tmp_path / "a.py").write_text('import os\ndef f(x):\n    os.system("rm " + x)\n', encoding="utf-8")
    rc = main(["check", str(tmp_path / "a.py"), "--root", str(tmp_path), "--no-packages", "--no-external",
               "--format", "json"])
    out = json.loads(capsys.readouterr().out)
    assert out["findings"][0]["rule_id"] == "TC-CMD-001"
    # 커밋 시점 점검은 HIGH 이상을 차단한다 (개발기획서 F1·3-5 : 취약 코드 커밋은 개발 단계에서 차단)
    assert rc == 1 and any("HIGH" in v for v in out["gate"]["violations"])
    # 가짜 키는 나눠 적어 저장소 자체 점검(dogfooding)에 걸리지 않게 한다
    (tmp_path / "b.py").write_text('K = "AKIA' + 'ABCDEFGHIJKLMNOP"\n', encoding="utf-8")
    rc = main(["check", str(tmp_path), "--root", str(tmp_path), "--no-packages", "--no-external", "--format", "sarif"])
    sarif = json.loads(capsys.readouterr().out)
    assert rc == 1 and sarif["version"] == "2.1.0"


def test_cli_sbom_aibom(tmp_path, capsys):
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")
    assert main(["sbom", "--root", str(tmp_path), "--no-syft", "-o", str(tmp_path / "s.json")]) == 0
    assert json.loads((tmp_path / "s.json").read_text())["components"][0]["name"] == "requests"
    (tmp_path / "model").mkdir()
    (tmp_path / "model" / "m.safetensors").write_bytes(b"\x02\x00\x00\x00\x00\x00\x00\x00{}")
    assert main(["aibom", "--root", str(tmp_path), "-o", str(tmp_path / "a.json")]) == 0
    assert main(["aibom-verify", str(tmp_path / "a.json"), "--root", str(tmp_path)]) == 0


def test_cli_ask_offline(capsys):
    assert main(["ask", "하드코딩된 비밀번호는 어떻게 관리해야 하나요?", "--offline-models"]) == 0
    out = capsys.readouterr().out
    assert "근거 문서" in out and "[1]" in out


def test_scenarios_offline_all_blocked():
    r = subprocess.run([sys.executable, str(ROOT / "scenarios" / "run_all.py"), "--offline"],
                       capture_output=True, text=True, encoding="utf-8", timeout=300)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "실행 5종 중 차단 5종" in r.stdout


def test_scenario5_lists_unique_cves(tmp_path):
    import importlib.util

    spec = importlib.util.spec_from_file_location("run_all", ROOT / "scenarios" / "run_all.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["run_all"] = mod
    spec.loader.exec_module(mod)
    r = mod.s5(tmp_path, True, None)
    assert r.blocked is True and r.evidence.count("CVE-2024-3094") == 1


def _load_run_all():
    import importlib.util

    spec = importlib.util.spec_from_file_location("run_all", ROOT / "scenarios" / "run_all.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["run_all"] = mod
    spec.loader.exec_module(mod)
    return mod


def test_scenario7_submits_hardened_pod_and_requires_signature_policy(monkeypatch):
    # 보안 설정을 모두 지킨 Pod 로 제출해, 차단 이유가 PodSecurity 가 아니라 서명 정책(trustchain-verify-images)임을 확인한다
    import subprocess as sp

    mod = _load_run_all()
    calls = []

    def fake_run(cmd, input=None, **kw):
        calls.append((cmd, input))
        # 정책 메시지(한국어 UTF-8)를 Windows 기본 인코딩(cp949)으로 읽으면 깨지므로 UTF-8 로 명시해야 한다
        assert kw.get("encoding") == "utf-8"
        return sp.CompletedProcess(cmd, 1, "", fake_run.stderr)

    monkeypatch.setattr(mod.shutil, "which", lambda name: "/usr/bin/kubectl")
    monkeypatch.setattr(mod.subprocess, "run", fake_run)
    img = "ghcr.io/o/app@sha256:" + "b" * 64
    fake_run.stderr = 'admission webhook "ivpol.validate.kyverno.svc" denied: Policy trustchain-verify-images failed'
    r = mod.s7(True, img)
    cmd, manifest = calls[0]
    # 남아 있는 같은 이름 Pod 때문에 UPDATE 로 바뀌지 않도록 : 서버 dry-run 생성 + generateName (흔적도 남기지 않음)
    assert cmd[:2] == ["kubectl", "create"] and "--dry-run=server" in cmd and "-f" in cmd
    assert "generateName: bypass-test-" in manifest
    for needle in (img, "allowPrivilegeEscalation: false", "runAsNonRoot: true", "memory:", "RuntimeDefault"):
        assert needle in manifest
    assert r.blocked is True
    fake_run.stderr = 'pods "bypass-test" is forbidden: violates PodSecurity "restricted:latest"'
    assert mod.s7(True, img).blocked is False                 # 서명 정책이 아닌 이유로 거부되면 시나리오 7 차단으로 세지 않음


def test_precommit_hooks_also_run_before_push():
    # 개발기획서 2-3 : "검사를 통과해야 push 할 수 있습니다" → 커밋 시점과 push 직전 모두 점검
    import yaml

    hooks = {h["id"]: h for h in yaml.safe_load((ROOT / ".pre-commit-hooks.yaml").read_text(encoding="utf-8"))}
    for hid in ("trustchain-check", "trustchain-pkg-strict"):
        assert {"pre-commit", "pre-push"} <= set(hooks[hid].get("stages", [])), hid
        assert hooks[hid].get("minimum_pre_commit_version") == "3.2.0", hid   # 단계 이름(pre-push)은 3.2.0 부터


def test_check_commit_policy_configurable(tmp_path, capsys):
    (tmp_path / "a.py").write_text('DB_PASSWORD = "S3cr3t-Prod-Passw0rd!"\n', encoding="utf-8")
    args = ["check", str(tmp_path / "a.py"), "--root", str(tmp_path), "--no-packages", "--no-external", "--format", "json"]
    assert main(args) == 1                                         # 하드코딩 비밀정보(HIGH) 커밋 차단
    capsys.readouterr()
    (tmp_path / "trustchain.toml").write_text("[check]\nmax_high = 5\n", encoding="utf-8")
    assert main(args) == 0                                         # 프로젝트가 커밋 기준을 완화할 수 있다
    capsys.readouterr()


def test_build_gate_policy_unchanged_by_commit_policy(tmp_path):
    from trustchain.core.config import load_config
    from trustchain.scan.gate import commit_policy

    cfg = load_config(tmp_path)
    assert cfg.gate.max_high > 0                                   # 빌드 게이트 기본값은 그대로 (CRITICAL 기준)
    c = commit_policy(cfg)
    assert c.gate.max_high == 0 and cfg.gate.max_high > 0          # 원래 설정을 바꾸지 않는다


def test_scenario3_uses_real_commit_policy():
    src = (ROOT / "scenarios" / "run_all.py").read_text(encoding="utf-8")
    body = src[src.index("def s3("):src.index("def s4(")]
    assert "commit_policy(" in body and "max_high = 0" not in body


def test_commit_policy_keeps_other_gate_settings(tmp_path):
    # [check] 는 심각도 한도만 바꾼다 : [gate] 의 신뢰 점수 하한·패키지 차단 같은 설정은 커밋 시점에도 그대로
    from trustchain.core.config import load_config
    from trustchain.scan.gate import commit_policy

    (tmp_path / "trustchain.toml").write_text("[gate]\nmin_trust_score = 60\nignore_unfixed = false\n", encoding="utf-8")
    c = commit_policy(load_config(tmp_path))
    assert c.gate.min_trust_score == 60 and c.gate.ignore_unfixed is False and c.gate.max_high == 0


def test_commit_check_does_not_block_on_dependency_advisories(cfg):
    # 커밋 시점 HIGH 차단은 작성 중인 코드(code)와 패키지 판정(package)에만 적용 : 의존성 권고문(dependency)은 빌드 게이트가 차단
    from trustchain.core.findings import Finding, Report, Severity
    from trustchain.scan.gate import commit_policy, evaluate

    c = commit_policy(cfg)
    dep = Finding("GHSA-x", "취약한 의존성", Severity.HIGH, "m", category="dependency")
    code = Finding("TC-SQL-001", "SQL 삽입", Severity.HIGH, "m", category="code")
    assert evaluate(c, Report([dep]), []) == []
    assert evaluate(c, Report([code]), []) != []
    assert evaluate(cfg, Report([dep]), []) == []                       # 빌드 게이트 기본(CRITICAL) 도 HIGH 허용
    crit = Finding("GHSA-y", "취약한 의존성", Severity.CRITICAL, "m", category="dependency")
    assert evaluate(cfg, Report([crit]), []) != [] and evaluate(c, Report([crit]), []) == []
