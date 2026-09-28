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
    assert rc == 0  # HIGH 는 기본 정책상 허용 (CRITICAL 0건 기준)
    (tmp_path / "b.py").write_text('K = "AKIAABCDEFGHIJKLMNOP"\n', encoding="utf-8")
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
