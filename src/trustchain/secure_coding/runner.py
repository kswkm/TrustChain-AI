"""F1 실행기 : 자체 룰 + (설치된 경우) Semgrep·Bandit 결과를 통합한다."""

from __future__ import annotations

import json
import shutil
import subprocess  # nosec - 고정 인자 리스트로만 외부 도구 실행
from pathlib import Path

from trustchain.core.config import Config
from trustchain.core.files import iter_files, read_text, rel
from trustchain.core.findings import Finding, Severity
from trustchain.secure_coding.rules import RULES, analyze_python, scan_text_for_tokens

TEXT_SUFFIXES = (".py", ".env", ".yml", ".yaml", ".json", ".toml", ".cfg", ".ini", ".sh", ".js", ".ts", ".txt", ".conf")
SEMGREP_RULES = Path(__file__).with_name("semgrep_kisa.yml")

# Bandit 테스트 ID -> 자체 룰 매핑 (중복 제거 및 한국어 안내 통일)
BANDIT_MAP = {
    "B301": "TC-DESER-001", "B403": "TC-DESER-001", "B506": "TC-DESER-001", "B614": "TC-DESER-001",
    "B602": "TC-CMD-001", "B605": "TC-CMD-001", "B608": "TC-SQL-001", "B307": "TC-CODE-001",
    "B105": "TC-SECRET-001", "B106": "TC-SECRET-001", "B324": "TC-CRYPTO-001", "B501": "TC-TLS-001",
    "B201": "TC-DEBUG-001", "B311": "TC-RAND-001", "B314": "TC-XML-001", "B306": "TC-TEMP-001",
}


def run_builtin(targets: list[Path], cfg: Config) -> list[Finding]:
    out: list[Finding] = []
    for target in targets:
        for p in iter_files(target, None, cfg.exclude):
            name = p.name.lower()
            if not (p.suffix.lower() in TEXT_SUFFIXES or name in ("dockerfile", ".env") or name.startswith(".env")):
                continue
            text = read_text(p)
            if text is None:
                continue
            rp = rel(p, cfg.root)
            if p.suffix.lower() == ".py":
                out.extend(analyze_python(text, rp))
            out.extend(scan_text_for_tokens(text, rp))
    return [f for f in out if f.rule_id not in cfg.disabled_rules]


def _run_tool(cmd: list[str], timeout: int = 300) -> str | None:
    exe = shutil.which(cmd[0])
    if not exe:
        return None
    try:
        r = subprocess.run([exe, *cmd[1:]], capture_output=True, text=True, encoding="utf-8", errors="replace",
                           timeout=timeout, check=False)  # nosec
    except (OSError, subprocess.TimeoutExpired):
        return None
    return r.stdout


def run_semgrep(targets: list[Path], cfg: Config) -> list[Finding]:
    stdout = _run_tool(
        ["semgrep", "scan", "--json", "--quiet", "--metrics=off", "--config", str(SEMGREP_RULES), *map(str, targets)]
    )
    if not stdout:
        return []
    try:
        data = json.loads(stdout)
    except ValueError:
        return []
    out = []
    for r in data.get("results", []):
        rid = r.get("check_id", "").split(".")[-1]
        base = RULES.get(rid)
        extra = r.get("extra", {})
        out.append(
            Finding(
                rule_id=rid if base else f"SEMGREP-{rid}",
                title=base.title if base else rid,
                severity=base.severity if base else Severity.parse(extra.get("severity")),
                message=extra.get("message", ""),
                file=rel(Path(r.get("path", "")), cfg.root),
                line=r.get("start", {}).get("line"),
                cwe=base.cwe if base else None,
                kisa=base.kisa if base else None,
                fix=base.fix if base else None,
                tool="semgrep",
            )
        )
    return out


def run_bandit(targets: list[Path], cfg: Config) -> list[Finding]:
    stdout = _run_tool(["bandit", "-r", "-f", "json", "-q", "-x", ",".join(cfg.exclude), *map(str, targets)])
    if not stdout:
        return []
    try:
        data = json.loads(stdout)
    except ValueError:
        return []
    out = []
    for r in data.get("results", []):
        mapped = BANDIT_MAP.get(r.get("test_id", ""))
        base = RULES.get(mapped) if mapped else None
        out.append(
            Finding(
                rule_id=mapped or f"BANDIT-{r.get('test_id')}",
                title=base.title if base else r.get("test_name", ""),
                severity=base.severity if base else Severity.parse(r.get("issue_severity")),
                message=r.get("issue_text", ""),
                file=rel(Path(r.get("filename", "")), cfg.root),
                line=r.get("line_number"),
                cwe=base.cwe if base else f"CWE-{r.get('issue_cwe', {}).get('id', '')}",
                kisa=base.kisa if base else None,
                fix=base.fix if base else r.get("more_info"),
                tool="bandit",
            )
        )
    return out


def run_secure_coding(targets: list[Path], cfg: Config, external: bool = True) -> list[Finding]:
    findings = run_builtin(targets, cfg)
    if external:
        findings += run_semgrep(targets, cfg) + run_bandit(targets, cfg)
    # 같은 위치의 같은 룰은 하나로 합친다 (자체 룰 우선)
    uniq: dict[tuple, Finding] = {}
    for f in findings:
        uniq.setdefault((f.rule_id, f.file, f.line), f)
    return [f for f in uniq.values() if f.severity.rank >= cfg.min_severity.rank]
