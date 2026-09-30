"""심사용 원클릭 시연 : Docker·PostgreSQL 없이 수집 API + 시연 데이터 + 대시보드를 한 번에 띄운다.

    pip install -e ".[server,dashboard]"
    python scripts/demo.py              # PyPI·OSV 실제 조회 (취약점 알림 생성, 네트워크 필요)
    python scripts/demo.py --offline    # PyPI 조회 없이 (네트워크가 없으면 알림 탭은 비어 있음)

1) .trustchain-demo/ 에 SQLite DB 를 새로 만들고 ingest·reader 토큰을 발급
2) 수집 API 를 띄워 scripts/seed_demo.py 의 시연 데이터를 적재
3) Streamlit 대시보드 실행 → http://localhost:8501  (Ctrl+C 로 모두 종료)
"""

from __future__ import annotations

import argparse
import importlib.util
import os
import subprocess
import sys
import time
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / ".trustchain-demo"
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

REQUIRED = {"fastapi": "server", "uvicorn": "server", "sqlalchemy": "server", "streamlit": "dashboard", "pandas": "dashboard"}


def check_deps(dashboard: bool) -> None:
    missing = [m for m, extra in REQUIRED.items() if (dashboard or extra == "server") and importlib.util.find_spec(m) is None]
    if missing:
        raise SystemExit(f"필요한 패키지가 없습니다: {', '.join(missing)}\n  pip install -e \".[server,dashboard]\"")


def issue_tokens() -> tuple[str, str]:
    from trustchain.server.auth import create_token
    from trustchain.server.db import init_db, make_engine, make_session_factory

    engine = make_engine()
    init_db(engine)
    with make_session_factory(engine)() as s:
        return create_token(s, "demo-ingest", "ingest"), create_token(s, "demo-dashboard", "reader")


def wait_healthy(url: str, proc: subprocess.Popen, log: Path, timeout: float = 60) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise SystemExit(f"수집 API 가 시작되지 않았습니다. 로그: {log}\n{log.read_text(encoding='utf-8', errors='replace')[-2000:]}")
        try:
            if httpx.get(url + "/healthz", timeout=2).status_code == 200:
                return
        except httpx.HTTPError:
            pass
        time.sleep(0.5)
    raise SystemExit(f"수집 API 응답 대기 시간 초과. 로그: {log}")


def summary(api: str, token: str) -> None:
    for s in httpx.get(api + "/api/v1/services", headers={"Authorization": f"Bearer {token}"}, timeout=30).json():
        print(f"  - {s['name']:<22} 신뢰 점수 {s['trust_score']:>3}/100 · 구성요소 {s['components']}개 · 미해결 알림 {s['open_alerts']}건")


def stop(*procs: subprocess.Popen | None) -> None:
    for p in procs:
        if p is not None and p.poll() is None:
            p.terminate()
            try:
                p.wait(timeout=10)
            except subprocess.TimeoutExpired:
                p.kill()


def main() -> int:
    ap = argparse.ArgumentParser(description="수집 API + 시연 데이터 + 대시보드 원클릭 실행 (SQLite)")
    ap.add_argument("--offline", action="store_true", help="PyPI 조회 없이 적재 (서버도 네트워크가 없으면 취약점 알림은 생기지 않음)")
    ap.add_argument("--port", type=int, default=8000, help="수집 API 포트")
    ap.add_argument("--dashboard-port", type=int, default=8501)
    ap.add_argument("--no-dashboard", action="store_true", help="데이터 적재·요약만 하고 종료")
    args = ap.parse_args()
    for s in (sys.stdout, sys.stderr):
        try:
            s.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
        except (AttributeError, ValueError):
            pass
    check_deps(dashboard=not args.no_dashboard)

    # 매 실행마다 새 DB (시연 데이터가 중복 적재되지 않도록)
    DATA.mkdir(exist_ok=True)
    db = DATA / "demo.db"
    db.unlink(missing_ok=True)
    env = {**os.environ, "TRUSTCHAIN_DATABASE_URL": f"sqlite:///{db.as_posix()}", "PYTHONUTF8": "1"}
    env.pop("TRUSTCHAIN_SCHEDULER", None)
    os.environ["TRUSTCHAIN_DATABASE_URL"] = env["TRUSTCHAIN_DATABASE_URL"]
    ingest, reader = issue_tokens()

    api = f"http://127.0.0.1:{args.port}"
    log = DATA / "server.log"
    server = dashboard = None
    try:
        print(f"[1/3] 수집 API 시작 : {api}  (로그 {log.relative_to(ROOT)})")
        with log.open("w", encoding="utf-8") as fh:
            server = subprocess.Popen([sys.executable, "-m", "uvicorn", "trustchain.server.app:create_app", "--factory",
                                       "--host", "127.0.0.1", "--port", str(args.port)], env=env, stdout=fh, stderr=fh)
        wait_healthy(api, server, log)

        print(f"[2/3] 시연 데이터 적재 ({'오프라인' if args.offline else 'PyPI·OSV 실제 조회'})")
        from seed_demo import seed

        seed(api, ingest, online=not args.offline)
        summary(api, reader)

        if args.no_dashboard:
            return 0
        print(f"[3/3] 대시보드 : http://localhost:{args.dashboard_port}   (종료: Ctrl+C)")
        dashboard = subprocess.Popen(
            [sys.executable, "-m", "streamlit", "run", str(ROOT / "src" / "trustchain" / "dashboard" / "app.py"),
             "--server.address", "127.0.0.1", "--server.port", str(args.dashboard_port), "--server.headless", "true",
             "--browser.gatherUsageStats", "false"],
            env={**env, "TRUSTCHAIN_API": api, "TRUSTCHAIN_TOKEN": reader})
        dashboard.wait()
    except KeyboardInterrupt:
        print("\n종료합니다.")
    finally:
        stop(dashboard, server)
    return 0


if __name__ == "__main__":
    sys.exit(main())
