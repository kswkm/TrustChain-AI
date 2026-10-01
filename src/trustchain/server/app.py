"""수집 API (FastAPI) : CI 리포트·SBOM·게이트 이벤트 수집, 조회, AI 어시스턴트 질의.

보안 설계
- 모든 /api 엔드포인트는 Bearer 토큰 인증 + 역할 기반 최소 권한 (reader / ingest / admin)
- 요청 본문 크기 제한, pydantic 스키마 검증 (extra 필드 거부)
- 오류 응답에 내부 정보(스택트레이스·쿼리) 미노출, 로그는 비밀정보 마스킹
- 보안 헤더, 문서(/docs) 기본 비활성화
"""
# 주의: FastAPI 가 create_app() 내부의 Annotated 의존성 별칭을 해석해야 하므로 `from __future__ import annotations` 를 쓰지 않는다.


import json
import os
import threading
import uuid
from contextlib import asynccontextmanager
from typing import Annotated, Any, Callable

from fastapi import Depends, FastAPI, Form, HTTPException, Query, Request, UploadFile
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker
from starlette.concurrency import run_in_threadpool

from trustchain import __version__
from trustchain.core.logging import get_logger
from trustchain.server import services
from trustchain.server.auth import authenticate, has_role
from trustchain.server.db import Alert, ApiToken, GateEvent, Service, init_db, make_engine, make_session_factory
from trustchain.server.schemas import AskIn, AskOut, EventIn, ReportIn, SBOMIn
from trustchain.server.uploads import check_suffix, read_limited, safe_filename

log = get_logger("trustchain.api")
MAX_BODY = int(os.environ.get("TRUSTCHAIN_MAX_BODY", str(20 * 1024 * 1024)))


class AppState:
    def __init__(self, sf: sessionmaker, monitor=None, assistant_factory: Callable[[], Any] | None = None):
        self.sf = sf
        self.monitor = monitor
        self._assistant_factory = assistant_factory
        self._assistant = None
        self._lock = threading.Lock()

    def assistant(self):
        with self._lock:
            if self._assistant is None and self._assistant_factory is not None:
                self._assistant = self._assistant_factory()
            return self._assistant

    def reset_assistant(self) -> None:
        with self._lock:
            self._assistant = None


def default_assistant_factory(sf: sessionmaker) -> Callable[[], Any]:
    def make():
        from trustchain.assistant.assistant import SecurityAssistant
        from trustchain.assistant.llm import default_llm
        from trustchain.assistant.retriever import default_reranker
        from trustchain.assistant.store import build_retriever
        from trustchain.assistant.text import default_embedder

        return SecurityAssistant(build_retriever(sf, default_embedder(), default_reranker()), default_llm())

    return make


def create_app(database_url: str | None = None, monitor=None, assistant_factory=None,
               start_scheduler: bool | None = None) -> FastAPI:
    engine = make_engine(database_url)
    init_db(engine)
    sf = make_session_factory(engine)
    if monitor is None and os.environ.get("TRUSTCHAIN_FEED", "1") == "1":
        from trustchain.feed.monitor import FeedMonitor
        from trustchain.feed.notify import notifier_from_env

        monitor = FeedMonitor(sf, notifier_from_env())
    state = AppState(sf, monitor, assistant_factory or default_assistant_factory(sf))
    run_sched = start_scheduler if start_scheduler is not None else os.environ.get("TRUSTCHAIN_SCHEDULER") == "1"

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        sched = None
        if run_sched and monitor is not None:
            from trustchain.feed.monitor import start_scheduler as _start

            sched = _start(monitor, int(os.environ.get("TRUSTCHAIN_FEED_INTERVAL_MIN", "10")))
        yield
        if sched is not None:
            sched.shutdown(wait=False)

    app = FastAPI(title="TrustChain AI Collector API", version=__version__, lifespan=lifespan,
                  docs_url="/docs" if os.environ.get("TRUSTCHAIN_DOCS") == "1" else None, redoc_url=None,
                  openapi_url="/openapi.json" if os.environ.get("TRUSTCHAIN_DOCS") == "1" else None)
    app.state.tc = state

    @app.middleware("http")
    async def limits_and_headers(request: Request, call_next):
        cl = request.headers.get("content-length")
        if cl is not None and (not cl.isdigit() or int(cl) > MAX_BODY):
            return JSONResponse({"detail": "요청 본문이 너무 큽니다"}, status_code=413)
        if request.method in ("POST", "PUT", "PATCH") and cl is None:
            body = await request.body()  # chunked 전송 : 실제 크기로 확인
            if len(body) > MAX_BODY:
                return JSONResponse({"detail": "요청 본문이 너무 큽니다"}, status_code=413)
        resp = await call_next(request)
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Cache-Control"] = "no-store"
        resp.headers["Referrer-Policy"] = "no-referrer"
        return resp

    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, exc: RequestValidationError):
        # 입력값 자체를 되돌려주지 않는다 (민감정보 반사 방지)
        errs = [{"loc": e.get("loc"), "msg": e.get("msg")} for e in exc.errors()[:20]]
        return JSONResponse({"detail": "입력값 검증 실패", "errors": errs}, status_code=422)

    @app.exception_handler(Exception)
    async def unhandled(request: Request, exc: Exception):
        rid = uuid.uuid4().hex[:12]
        log.error("처리되지 않은 오류 id=%s path=%s type=%s", rid, request.url.path, exc.__class__.__name__)
        return JSONResponse({"detail": "요청을 처리할 수 없습니다", "request_id": rid}, status_code=500)

    def db():
        with state.sf() as s:
            yield s

    DB = Annotated[Session, Depends(db)]

    def require(role: str):
        def dep(request: Request, s: DB) -> ApiToken:
            auth = request.headers.get("authorization", "")
            token = auth[7:].strip() if auth.lower().startswith("bearer ") else None
            tok = authenticate(s, token)
            if tok is None:
                raise HTTPException(401, "인증 실패", headers={"WWW-Authenticate": "Bearer"})
            if not has_role(tok, role):
                raise HTTPException(403, "권한 없음")
            return tok

        return dep

    Reader = Annotated[ApiToken, Depends(require("reader"))]
    Ingest = Annotated[ApiToken, Depends(require("ingest"))]
    Admin = Annotated[ApiToken, Depends(require("admin"))]

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    # ---------------- 수집 (CI) ----------------
    @app.post("/api/v1/reports", status_code=201)
    def post_report(body: ReportIn, s: DB, _: Ingest) -> dict[str, Any]:
        rep = services.ingest_report(s, body)
        return {"id": rep.id, "passed": rep.passed}

    @app.post("/api/v1/sboms", status_code=201)
    def post_sbom(body: SBOMIn, s: DB, _: Ingest) -> dict[str, Any]:
        art, n = services.ingest_sbom(s, body)
        stats = None
        if state.monitor is not None and os.environ.get("TRUSTCHAIN_MATCH_ON_INGEST", "1") == "1":
            try:
                stats = state.monitor.match_artifact(art.id).to_dict()
            except Exception as e:  # 매칭 실패가 수집을 막지 않도록
                log.warning("SBOM 즉시 매칭 실패: %s", e.__class__.__name__)
        return {"artifact_id": art.id, "components": n, "match": stats}

    @app.post("/api/v1/sboms/upload", status_code=201)
    async def upload_sbom(s: DB, _: Ingest, file: UploadFile, service: Annotated[str, Form()],
                          digest: Annotated[str | None, Form()] = None,
                          image: Annotated[str | None, Form()] = None) -> dict[str, Any]:
        # 파일명은 응답 표시용으로만 정규화해 쓰고 서버 경로에 저장하지 않는다 (1MB 초과분은 요청 동안만 임시 파일)
        name = safe_filename(file.filename)
        check_suffix(name)
        raw = await read_limited(file)
        try:
            sbom = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError, RecursionError):
            raise HTTPException(422, "JSON 형식이 아닙니다") from None
        try:
            body = SBOMIn(service=service, digest=digest, image=image, sbom=sbom)
        except ValidationError as e:
            raise HTTPException(422, [{"loc": x.get("loc"), "msg": x.get("msg")} for x in e.errors()[:20]]) from None
        out = await run_in_threadpool(post_sbom, body, s, _)
        return out | {"filename": name}

    @app.post("/api/v1/events", status_code=201)
    def post_event(body: EventIn, s: DB, _: Ingest) -> dict[str, Any]:
        ev = services.record_event(s, body)
        return {"id": ev.id}

    # ---------------- 조회 ----------------
    @app.get("/api/v1/services")
    def get_services(s: DB, _: Reader) -> list[dict[str, Any]]:
        return services.list_services(s)

    @app.get("/api/v1/services/{name}/components")
    def get_components(name: str, s: DB, _: Reader,
                       q: Annotated[str | None, Query(max_length=100)] = None) -> list[dict[str, Any]]:
        return services.service_components(s, name[:128], q)

    @app.get("/api/v1/services/{name}/findings")
    def get_findings(name: str, s: DB, _: Reader) -> list[dict[str, Any]]:
        return services.latest_findings(s, name[:128])

    @app.get("/api/v1/events")
    def get_events(s: DB, _: Reader, service: Annotated[str | None, Query(max_length=128)] = None,
                   blocked_only: bool = False, limit: Annotated[int, Query(ge=1, le=500)] = 100) -> list[dict]:
        stmt = select(GateEvent, Service.name).join(Service, Service.id == GateEvent.service_id)
        if service:
            stmt = stmt.where(Service.name == service)
        if blocked_only:
            stmt = stmt.where(GateEvent.passed.is_(False))
        rows = s.execute(stmt.order_by(GateEvent.created_at.desc(), GateEvent.id.desc()).limit(limit)).all()
        return [{"service": n, "stage": e.stage, "image": e.image, "passed": e.passed, "reason": e.reason,
                 "created_at": e.created_at.isoformat()} for e, n in rows]

    @app.get("/api/v1/alerts")
    def get_alerts(s: DB, _: Reader, open_only: bool = True,
                   limit: Annotated[int, Query(ge=1, le=500)] = 100) -> list[dict]:
        stmt = select(Alert, Service.name).join(Service, Service.id == Alert.service_id)
        if open_only:
            stmt = stmt.where(Alert.resolved.is_(False))
        rows = s.execute(stmt.order_by(Alert.matched_at.desc()).limit(limit)).all()
        return [{"id": a.id, "service": n, "vuln_id": a.vuln_id, "component": a.component, "version": a.version,
                 "severity": a.severity, "fixed": a.fixed_versions, "matched_at": a.matched_at.isoformat(),
                 "notified_at": a.notified_at.isoformat() if a.notified_at else None} for a, n in rows]

    # ---------------- AI 어시스턴트 ----------------
    @app.post("/api/v1/assistant/ask", response_model=AskOut)
    def ask(body: AskIn, s: DB, _: Reader) -> AskOut:
        assistant = state.assistant()
        if assistant is None:
            raise HTTPException(503, "어시스턴트를 사용할 수 없습니다")
        ctx: dict[str, Any] = {}
        findings: list[dict[str, Any]] = []
        if body.service:
            comps = services.service_components(s, body.service, limit=300)
            findings = services.latest_findings(s, body.service)
            ctx["서비스"] = body.service
            ctx["SBOM 구성요소(일부)"] = ", ".join(f"{c['name']}=={c['version']}" for c in comps[:80])
            ctx["최근 스캔 결과"] = "; ".join(f"{f['severity']} {f['rule_id']} {f.get('title', '')}"
                                          for f in findings[:30])
        ans = assistant.ask(body.question, ctx or None, body.top_k, findings=findings or None)
        return AskOut(answer=ans.answer, citations=ans.citations, grounded=ans.grounded,
                      priorities=ans.priorities[:10])

    # ---------------- 관리 ----------------
    @app.post("/api/v1/admin/feed/run")
    def run_feed(_: Admin) -> dict[str, Any]:
        if state.monitor is None:
            raise HTTPException(503, "피드 모니터 비활성화")
        return state.monitor.run_once().to_dict()

    @app.post("/api/v1/admin/assistant/reload")
    def reload_assistant(_: Admin) -> dict[str, str]:
        state.reset_assistant()
        return {"status": "reloaded"}

    return app
