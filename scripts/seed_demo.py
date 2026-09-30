"""로컬 시연용 데이터 적재 : 실제 스캔을 돌려 결과를 수집 API 로 전송한다 (대시보드 확인용).

    set TRUSTCHAIN_TOKEN=<ingest 이상 토큰>
    python scripts/seed_demo.py --server http://127.0.0.1:8000

적재 내용
- mnist-api          : demo/mnist-api 에 대한 실제 게이트 결과 + SBOM(+AI-BOM)
- trustchain-platform: 저장소 루트에 대한 실제 게이트 결과 + SBOM
- legacy-api         : 취약 버전(PyYAML 5.3.1, requests 2.31.0)을 고정한 시연용 프로젝트.
                       SBOM 수집 시 서버가 OSV 를 실제 조회해 취약점 알림을 만든다 (네트워크 필요)
- attack-scenarios   : scenarios/run_all.py 의 시나리오 1~5 차단 결과를 게이트 이벤트로 기록
"""

from __future__ import annotations

import argparse
import os
import sys
import tempfile
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scenarios"))

from trustchain.bom.aibom import generate_aibom, merge_boms  # noqa: E402
from trustchain.bom.sbom import sbom_from_project  # noqa: E402
from trustchain.core.config import load_config  # noqa: E402
from trustchain.scan.gate import run_gate  # noqa: E402

FAKE_DIGEST = {"mnist-api": "1", "trustchain-platform": "2", "legacy-api": "3"}


def post(client: httpx.Client, path: str, body: dict) -> dict:
    r = client.post(path, json=body)
    if r.status_code >= 300:
        raise SystemExit(f"{path} 실패: HTTP {r.status_code} {r.text[:200]}")
    return r.json()


def report_body(service: str, outcome, digest: str) -> dict:
    d = outcome.to_dict()
    keys = ("rule_id", "title", "severity", "message", "category", "file", "line", "cwe", "kisa", "fix", "tool")
    return {"service": service, "repo": "github.com/kswkm/TrustChain-AI", "digest": digest,
            "passed": outcome.passed, "summary": d["summary"], "violations": outcome.violations,
            "findings": [{k: f.get(k) for k in keys} for f in d["findings"]][:5000]}


def seed_project(client: httpx.Client, service: str, root: Path, stages: set[str], online: bool) -> None:
    cfg = load_config(root)
    cfg.offline = not online
    if not online:
        stages = stages - {"packages"}
    outcome = run_gate(cfg, stages=stages, external_tools=False)
    digest = "sha256:" + FAKE_DIGEST[service] * 64
    post(client, "/api/v1/reports", report_body(service, outcome, digest))
    bom = merge_boms(sbom_from_project(root, service), generate_aibom(root, cfg.model_dirs, cfg.exclude, service))
    res = post(client, "/api/v1/sboms", {"service": service, "digest": digest, "sbom": bom})
    print(f"[{service}] 게이트 {'통과' if outcome.passed else '실패'} {outcome.report.counts()} "
          f"| SBOM 구성요소 {res['components']}개 | 매칭 {res.get('match')}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--server", default="http://127.0.0.1:8000")
    ap.add_argument("--offline", action="store_true", help="PyPI 조회 없이 적재 (서버도 네트워크가 없으면 취약점 알림은 생기지 않음)")
    args = ap.parse_args()
    for s in (sys.stdout, sys.stderr):
        try:
            s.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
        except (AttributeError, ValueError):
            pass
    token = os.environ.get("TRUSTCHAIN_TOKEN")
    if not token:
        raise SystemExit("TRUSTCHAIN_TOKEN 환경변수(ingest 권한 토큰)가 필요합니다")
    seed(args.server, token, online=not args.offline)
    print("완료 - 대시보드에서 확인하세요.")
    return 0


def seed(server: str, token: str, online: bool = True) -> None:
    """수집 API 에 시연 데이터를 적재한다 (scripts/demo.py 에서도 호출)."""
    with httpx.Client(base_url=server.rstrip("/"), headers={"Authorization": f"Bearer {token}"},
                      timeout=120) as client:
        seed_project(client, "mnist-api", ROOT / "demo" / "mnist-api", {"code", "packages", "models", "docker"}, online)
        seed_project(client, "trustchain-platform", ROOT, {"code", "packages", "docker", "iac"}, online)
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            (p / "requirements.txt").write_text("PyYAML==5.3.1\nrequests==2.31.0\nfastapi==0.115.6\n", encoding="utf-8")
            (p / "app.py").write_text(
                'import yaml, requests\nfrom fastapi import FastAPI\napp = FastAPI()\nAPI_TOKEN = "legacy-hardcoded-123"\n'
                "def load(s):\n    return yaml.load(s)\n", encoding="utf-8")
            seed_project(client, "legacy-api", p, {"code", "packages"}, online)

        # 공격 시나리오 1~5 를 실제로 재현하고 차단 결과를 이벤트로 기록
        import run_all

        stages = {1: "commit", 2: "commit", 3: "commit", 4: "build", 5: "build"}
        fns = [run_all.s1, run_all.s2, run_all.s3, run_all.s4]
        results = []
        for fn in fns:
            with tempfile.TemporaryDirectory() as d:
                results.append(fn(Path(d), True))
        with tempfile.TemporaryDirectory() as d:
            results.append(run_all.s5(Path(d), True, None))
        for r in results:
            post(client, "/api/v1/events", {"service": "attack-scenarios", "stage": stages[r.no],
                                            "passed": not r.blocked, "reason": f"[시나리오 {r.no}] {r.title}: {r.evidence}"[:4000]})
        print(f"[attack-scenarios] 시나리오 {len(results)}종 기록 (차단 {sum(1 for r in results if r.blocked)}종)")


if __name__ == "__main__":
    sys.exit(main())
