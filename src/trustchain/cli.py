"""TrustChain CLI.

    trustchain check [파일...]            커밋 전 점검 (F1 시큐어코딩 + F2·F3 패키지 판정 + F4 신뢰 점수)
    trustchain pkg <이름> [--version V]   AI 가 제안한 패키지를 설치 전에 판정
    trustchain gate                       빌드 보안 스캔 게이트 (F5)
    trustchain scan-model <경로>          모델 파일 악성 pickle 스캔
    trustchain sbom / aibom               SBOM · AI-BOM 생성 (F6), aibom-verify 로 해시 대조
    trustchain verify <image@digest>      Verify Gate (F8)
    trustchain iac [경로]                 Kubernetes/Dockerfile/IaC 점검 (F9)
    trustchain upload ...                 수집 API 로 결과 전송
    trustchain server | token | feed      수집 API·토큰·피드 모니터 (F10)
    trustchain kb | ask | eval            AI 보안 어시스턴트 (F11)
    trustchain model train|eval           패키지 위험 분류 모델
    trustchain pr-draft                   취약 의존성 수정 PR 초안
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess  # nosec - git 고정 인자 호출
import sys
from pathlib import Path
from typing import Any

from trustchain import __version__
from trustchain.core.config import Config, load_config
from trustchain.core.findings import Report, Severity

COLORS = {"CRITICAL": "\033[1;31m", "HIGH": "\033[31m", "MEDIUM": "\033[33m", "LOW": "\033[36m", "INFO": "\033[2m"}
RESET = "\033[0m"
VERDICT_COLOR = {"정상": "\033[32m", "주의": "\033[33m", "차단": "\033[1;31m"}


def _utf8() -> None:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
        except (AttributeError, ValueError):
            pass


def _color() -> bool:
    return sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def _c(text: str, code: str) -> str:
    return f"{code}{text}{RESET}" if _color() else text


def print_report(report: Report, violations: list[str] | None = None, verdicts: list | None = None) -> None:
    for f in report.sorted():
        loc = f"{f.file}:{f.line}" if f.file and f.line else (f.file or "-")
        print(f"{_c(f.severity.value.ljust(8), COLORS[f.severity.value])} {f.rule_id:<16} {loc}")
        print(f"         {f.title} - {f.message}")
        if f.kisa:
            print(f"         KISA: {f.kisa}  {f.cwe or ''}")
        if f.fix and f.severity.rank >= Severity.MEDIUM.rank:
            for line in f.fix.splitlines()[:4]:
                print(f"         ↳ {line}")
    if verdicts:
        print("\n패키지 판정")
        for v in verdicts:
            ts = f" 신뢰점수 {v.trust.total}({v.trust.grade()})" if v.trust else ""
            print(f"  {_c(v.verdict, VERDICT_COLOR[v.verdict])} {v.raw_name}{('==' + v.version) if v.version else ''}{ts}")
            for r in v.reasons[:4]:
                print(f"       - {r}")
    counts = report.counts()
    print("\n요약: " + ", ".join(f"{k} {v}" for k, v in counts.items() if v) if any(counts.values()) else "\n요약: 발견 없음")
    if violations is not None:
        if violations:
            print(_c("게이트 실패: ", COLORS["CRITICAL"]) + "; ".join(violations))
        else:
            print(_c("게이트 통과", "\033[32m"))


def _emit(args: argparse.Namespace, payload: dict[str, Any], report: Report | None = None) -> None:
    out = getattr(args, "output", None)
    if getattr(args, "format", "text") == "sarif" and report is not None:
        text = json.dumps(report.to_sarif(), ensure_ascii=False, indent=2)
    else:
        text = json.dumps(payload, ensure_ascii=False, indent=2, default=str)
    if out:
        Path(out).parent.mkdir(parents=True, exist_ok=True)
        Path(out).write_text(text, encoding="utf-8")
    elif getattr(args, "format", "text") in ("json", "sarif"):
        print(text)


def _staged_files(root: Path) -> list[Path]:
    git = shutil.which("git")
    if not git:
        return []
    r = subprocess.run([git, "diff", "--cached", "--name-only", "--diff-filter=ACMR"], cwd=root,  # nosec
                       capture_output=True, text=True, check=False)
    return [root / p for p in r.stdout.splitlines() if p.strip()]


def _cfg(args: argparse.Namespace) -> Config:
    cfg = load_config(getattr(args, "root", "."))
    if getattr(args, "offline", False):
        cfg.offline = True
    return cfg


# ---------------- commands ----------------
def cmd_check(args: argparse.Namespace) -> int:
    from trustchain.scan.gate import run_gate

    cfg = _cfg(args)
    targets = [Path(p) for p in args.paths] if args.paths else None
    if args.staged:
        targets = _staged_files(cfg.root) or None
        if targets is None:
            print("스테이징된 파일이 없습니다.")
            return 0
    stages = {"code", "packages"} if not args.no_packages else {"code"}
    outcome = run_gate(cfg, targets, stages=stages, external_tools=not args.no_external)
    if args.strict_packages:
        warned = [v.raw_name for v in outcome.verdicts if v.verdict == "주의"]
        if warned:
            outcome.violations.append(f"주의 판정 패키지(strict): {', '.join(warned)}")
    if args.format == "text":
        print_report(outcome.report, outcome.violations, outcome.verdicts)
    _emit(args, outcome.to_dict(), outcome.report)
    return 0 if outcome.passed else 1


def cmd_pkg(args: argparse.Namespace) -> int:
    from trustchain.scan.gate import make_checker

    cfg = _cfg(args)
    checker = make_checker(cfg, with_scorecard=not args.no_scorecard)
    worst = 0
    results = []
    for name in args.names:
        n, _, ver = name.partition("==")
        v = checker.check_name(n, n, args.version or ver or None)
        results.append(v.to_dict())
        worst = max(worst, {"정상": 0, "주의": 1, "차단": 2}[v.verdict])
        if args.format == "text":
            print(f"{_c(v.verdict, VERDICT_COLOR[v.verdict])} {v.raw_name}  (정상 {v.probs.get('정상', '-')}, "
                  f"주의 {v.probs.get('주의', '-')}, 차단 {v.probs.get('차단', '-')})")
            if v.model:
                print(f"   판정 모델 : {v.model}")
            for r in v.reasons:
                print(f"   - {r}")
            if v.trust:
                print(f"   신뢰 점수 {v.trust.total}/100 ({v.trust.grade()}) : 취약점 {v.trust.vulnerability}/40, "
                      f"유지관리 {v.trust.maintenance}/25, 관리자 {v.trust.maintainers}/10, Scorecard {v.trust.scorecard}/25")
                for nte in v.trust.notes:
                    print(f"     · {nte}")
    _emit(args, {"packages": results})
    return 2 if worst == 2 else (1 if worst == 1 and args.strict else 0)


def cmd_gate(args: argparse.Namespace) -> int:
    from trustchain.scan.gate import run_gate

    cfg = _cfg(args)
    stages = set(args.stages.split(",")) if args.stages else None
    outcome = run_gate(cfg, stages=stages, image=args.image,
                       trivy_report=Path(args.trivy_report) if args.trivy_report else None,
                       external_tools=not args.no_external,
                       # 빌드 게이트에서만 pip-audit · OSV-Scanner 실행 (커밋 전 `check` 는 가볍게 유지)
                       dependency_scanners=not args.no_external)
    if args.format == "text":
        print_report(outcome.report, outcome.violations, outcome.verdicts)
    _emit(args, outcome.to_dict(), outcome.report)
    if args.sarif:
        Path(args.sarif).write_text(json.dumps(outcome.report.to_sarif(), ensure_ascii=False, indent=2), "utf-8")
    return 0 if outcome.passed else 1


def cmd_scan_model(args: argparse.Namespace) -> int:
    from trustchain.scan.modelscan import scan_models

    cfg = _cfg(args)
    results, findings = scan_models(Path(args.path), cfg.exclude, cfg.root)
    rep = Report(findings)
    if args.format == "text":
        for r in results:
            state = "위험" if r.dangerous else ("검토" if r.issues or r.unknown else "안전")
            print(f"[{state}] {r.path} ({r.format}) globals={len(r.globals)}"
                  + (f" dangerous={r.dangerous}" if r.dangerous else ""))
        print_report(rep)
    _emit(args, {"results": [r.__dict__ for r in results], **rep.to_dict()}, rep)
    return 1 if any(f.severity == Severity.CRITICAL for f in findings) else 0


def cmd_sbom(args: argparse.Namespace) -> int:
    from trustchain.bom.aibom import generate_aibom, merge_boms
    from trustchain.bom.sbom import generate_sbom, write_bom

    cfg = _cfg(args)
    name = args.name or cfg.root.name
    bom = generate_sbom(cfg.root, name, args.version, target=args.image, use_syft=not args.no_syft,
                        from_env=args.from_env)
    if args.with_aibom:
        bom = merge_boms(bom, generate_aibom(cfg.root, cfg.model_dirs, cfg.exclude, name))
    write_bom(bom, Path(args.output))
    print(f"SBOM 생성: {args.output} (구성요소 {len(bom.get('components', []))}개)")
    return 0


def cmd_aibom(args: argparse.Namespace) -> int:
    from trustchain.bom.aibom import aibom_findings, generate_aibom
    from trustchain.bom.sbom import write_bom

    cfg = _cfg(args)
    bom = generate_aibom(cfg.root, cfg.model_dirs, cfg.exclude, args.name or cfg.root.name)
    write_bom(bom, Path(args.output))
    models = [c for c in bom["components"] if c["type"] == "machine-learning-model"]
    print(f"AI-BOM 생성: {args.output} (모델 {len(models)}개, 데이터셋 {len(bom['components']) - len(models)}개)")
    for f in aibom_findings(bom):
        print(f"  {f.severity.value} {f.message}")
    return 0


def cmd_aibom_verify(args: argparse.Namespace) -> int:
    from trustchain.bom.aibom import load_bom, verify_aibom

    checks = verify_aibom(load_bom(Path(args.aibom)), Path(args.root))
    ok = all(c.ok for c in checks)  # 모델이 없는 프로젝트는 검증할 대상이 없으므로 통과
    for c in checks:
        print(f"[{'OK' if c.ok else 'FAIL'}] {c.name} {c.path or ''} {c.reason}")
    if not checks:
        print("AI-BOM 에 검증할 모델이 없습니다.")
    return 0 if ok else 1


def cmd_verify(args: argparse.Namespace) -> int:
    from trustchain.attest.verify import VerifyGate

    cfg = _cfg(args)
    pol = cfg.provenance
    pol.source_repo = args.repo or pol.source_repo
    pol.branch = args.branch if args.branch is not None else pol.branch
    pol.workflow_path = args.workflow or pol.workflow_path
    pol.signer_repo = args.signer_repo or pol.signer_repo
    if not pol.source_repo:
        print("소스 저장소(--repo github.com/org/repo 또는 [tool.trustchain.provenance].source_repo)가 필요합니다.")
        return 2
    res = VerifyGate(pol, require_sbom=not args.no_sbom, require_aibom=args.require_aibom).verify(args.image)
    if args.format == "text":
        for c in res.checks:
            print(f"[{_c('PASS', chr(27) + '[32m') if c.passed else _c('FAIL', COLORS['CRITICAL'])}] {c.name} {c.detail}")
        print("Verify Gate:", "통과 - 배포 허용" if res.passed else "실패 - 배포 차단")
    _emit(args, res.to_dict())
    if args.report_to:
        _upload(args.report_to, "/api/v1/events", {
            "service": args.service or pol.source_repo.split("/")[-1], "stage": "deploy", "image": args.image,
            "passed": res.passed, "reason": "; ".join(f"{c.name}: {c.detail}" for c in res.checks if not c.passed),
        })
    return 0 if res.passed else 1


def cmd_iac(args: argparse.Namespace) -> int:
    from trustchain.iac.k8s import check_k8s, run_checkov
    from trustchain.scan.image import check_dockerfiles

    cfg = _cfg(args)
    root = Path(args.path)
    rep = Report()
    rep.extend(check_k8s(root, cfg.exclude))
    rep.extend(check_dockerfiles(root, cfg.exclude))
    if not args.no_external:
        rep.extend(run_checkov(root, cfg.exclude)[0])
    if args.format == "text":
        print_report(rep)
    _emit(args, rep.to_dict(), rep)
    return 1 if cfg.gate.violations(rep.counts()) else 0


def _upload(server: str, path: str, payload: dict[str, Any]) -> dict[str, Any]:
    import httpx

    if not (server.startswith("https://") or server.startswith(("http://localhost", "http://127.0.0.1",
                                                                  "http://trustchain-api"))):
        raise SystemExit("수집 API 는 https 로만 전송합니다 (로컬/클러스터 내부 제외)")
    token = os.environ.get("TRUSTCHAIN_TOKEN")
    if not token:
        raise SystemExit("TRUSTCHAIN_TOKEN 환경변수가 필요합니다")
    r = httpx.post(server.rstrip("/") + path, json=payload, headers={"Authorization": f"Bearer {token}"}, timeout=60)
    if r.status_code >= 300:
        raise SystemExit(f"업로드 실패: HTTP {r.status_code}")
    return r.json()


def cmd_upload(args: argparse.Namespace) -> int:
    data = json.loads(Path(args.file).read_text(encoding="utf-8")) if args.file else {}
    meta = {k: v for k, v in {"image": args.image, "digest": args.digest, "git_sha": args.git_sha}.items() if v}
    if args.kind == "report":
        payload = {"service": args.service, "repo": args.repo, **meta,
                   "passed": data.get("gate", {}).get("passed", False), "summary": data.get("summary", {}),
                   "violations": data.get("gate", {}).get("violations", []),
                   "findings": [{k: f.get(k) for k in ("rule_id", "title", "severity", "message", "category", "file",
                                                       "line", "cwe", "kisa", "fix", "tool", "extra")}
                                for f in data.get("findings", [])][:5000],
                   "signed": args.signed, "provenance": args.provenance}
        res = _upload(args.server, "/api/v1/reports", payload)
    elif args.kind == "sbom":
        res = _upload(args.server, "/api/v1/sboms", {"service": args.service, **meta, "sbom": data})
    else:
        res = _upload(args.server, "/api/v1/events", {"service": args.service, "stage": args.stage,
                                                      "image": args.image, "passed": args.passed == "true",
                                                      "reason": args.reason or ""})
    print(json.dumps(res, ensure_ascii=False))
    return 0


def cmd_server(args: argparse.Namespace) -> int:
    import uvicorn

    from trustchain.server.app import create_app

    uvicorn.run(create_app(), host=args.host, port=args.port, proxy_headers=True, server_header=False)
    return 0


def cmd_token(args: argparse.Namespace) -> int:
    from trustchain.server.auth import create_token
    from trustchain.server.db import init_db, make_engine, make_session_factory

    engine = make_engine()
    init_db(engine)
    with make_session_factory(engine)() as s:
        tok = create_token(s, args.name, args.role)
    print("토큰은 다시 표시되지 않습니다. 안전한 곳(GitHub Secrets 등)에 저장하세요.")
    print(tok)
    return 0


def cmd_feed(args: argparse.Namespace) -> int:
    from trustchain.feed.monitor import FeedMonitor
    from trustchain.feed.notify import notifier_from_env
    from trustchain.server.db import init_db, make_engine, make_session_factory

    engine = make_engine()
    init_db(engine)
    mon = FeedMonitor(make_session_factory(engine), notifier_from_env(),
                      ecosystems=args.ecosystems.split(",") if args.ecosystems else None)
    print(json.dumps(mon.run_once(args.max).to_dict(), ensure_ascii=False))
    return 0


def _assistant(offline_models: bool, osv_dir: str | None = None, cwe_csv: str | None = None,
               nvd_dir: str | None = None):
    from trustchain.assistant.assistant import SecurityAssistant
    from trustchain.assistant.llm import default_llm
    from trustchain.assistant.retriever import HybridRetriever, LexicalReranker, default_reranker
    from trustchain.assistant.text import HashingEmbedder, default_embedder

    if os.environ.get("TRUSTCHAIN_DATABASE_URL"):
        from trustchain.assistant.store import build_retriever
        from trustchain.server.db import init_db, make_engine, make_session_factory

        engine = make_engine()
        init_db(engine)
        emb = HashingEmbedder() if offline_models else default_embedder()
        retr = build_retriever(make_session_factory(engine), emb,
                               LexicalReranker() if offline_models else default_reranker())
    else:
        from trustchain.assistant.ingest import knowledge_chunks

        emb = HashingEmbedder() if offline_models else default_embedder()
        retr = HybridRetriever(knowledge_chunks(osv_dir, cwe_csv, nvd_dir), emb,
                               reranker=LexicalReranker() if offline_models else default_reranker())
    return SecurityAssistant(retr, default_llm())


def cmd_kb(args: argparse.Namespace) -> int:
    from trustchain.assistant.ingest import knowledge_chunks
    from trustchain.assistant.store import upsert_chunks
    from trustchain.assistant.text import HashingEmbedder, default_embedder
    from trustchain.server.db import init_db, make_engine, make_session_factory

    engine = make_engine()
    init_db(engine)
    chunks = knowledge_chunks(args.osv_dir, args.cwe_csv, args.nvd_dir)
    emb = HashingEmbedder() if args.offline_models else default_embedder()
    with make_session_factory(engine)() as s:
        n = upsert_chunks(s, chunks, emb)
    print(f"지식베이스 적재: {n}개 청크 (임베딩 {emb.__class__.__name__}, {emb.dim}차원)")
    return 0


def cmd_ask(args: argparse.Namespace) -> int:
    findings = None
    used = None
    if args.report:
        data = json.loads(Path(args.report).read_text(encoding="utf-8"))
        findings = data.get("findings", [])
        if args.root:
            from trustchain.packages.imports import collect_imports

            used = set(collect_imports(Path(args.root), load_config(args.root).exclude).keys())
    ans = _assistant(args.offline_models).ask(args.question, top_k=args.top_k, findings=findings, used_modules=used)
    print(ans.answer)
    if ans.priorities:
        print("\n위험 우선순위")
        for p in ans.priorities[:10]:
            print(f"  {p['rank']}. [{p['score']}] {p['id']} {p['package'] or ''} - {', '.join(p['reasons'])}")
    print("\n근거 문서")
    for c in ans.citations:
        print(f"  [{c['n']}] {c['title']} {c.get('url') or ''}")
    if not ans.grounded:
        print("  (근거 없음)")
    return 0


def cmd_eval(args: argparse.Namespace) -> int:
    from trustchain.assistant.evaluate import answer_metrics, compare_modes, load_eval_set

    assistant = _assistant(args.offline_models, args.osv_dir, args.cwe_csv, args.nvd_dir)
    items = load_eval_set(Path(args.evalset))
    res = {"n": len(items), "kb_chunks": len(assistant.retriever.chunks), "retrieval": compare_modes(assistant.retriever, items, k=args.k)}
    if args.answers:
        res["answers"] = answer_metrics(assistant, items, k=args.k)
    print(json.dumps(res, ensure_ascii=False, indent=2))
    if args.output:
        Path(args.output).write_text(json.dumps(res, ensure_ascii=False, indent=2), encoding="utf-8")
    return 0


def cmd_model(args: argparse.Namespace) -> int:
    if args.action == "real-data":
        from trustchain.core.http import CachedClient
        from trustchain.packages.pypi import PyPIClient
        from trustchain.packages.realeval import collect

        client = PyPIClient(CachedClient(Path(os.environ.get("TRUSTCHAIN_CACHE", ".trustchain-cache")), ttl=7 * 86400))
        print(json.dumps(collect(Path(args.data_dir), client, seed=args.seed), ensure_ascii=False, indent=2))
        return 0
    if args.action == "eval-real":
        from trustchain.packages.classifier import KerasModel, LinearModel
        from trustchain.packages.realeval import evaluate_real

        if not (Path(args.data_dir) / "manifest.json").is_file():
            print(f"실측 스냅샷이 없습니다: {args.data_dir}. 먼저 `trustchain model real-data` 를 실행하세요.", file=sys.stderr)
            return 2
        # --out 을 명시하지 않으면 작업 디렉터리의 파일과 무관하게 탑재 모델로 평가한다 (문서 수치 재현)
        if not args.out:
            model = LinearModel.load_default()
        elif args.out.endswith(".keras"):
            model = KerasModel(Path(args.out))
        else:
            model = LinearModel.load(Path(args.out))
        print(json.dumps(evaluate_real(model, Path(args.data_dir)), ensure_ascii=False, indent=2))
        return 0

    from trustchain.packages.training import build_dataset, evaluate, split, train_and_save

    args.out = args.out or "package_model.json"
    if args.action == "train":
        rep = train_and_save(args.out, backend=args.backend, seed=args.seed)
    else:
        from trustchain.packages.classifier import KerasModel, LinearModel

        model = KerasModel(Path(args.out)) if args.out.endswith(".keras") else (
            LinearModel.load(Path(args.out)) if Path(args.out).is_file() else LinearModel.load_default())
        _, test = split(build_dataset(seed=args.seed), seed=args.seed)
        rep = evaluate(model, test)
    print(json.dumps(rep, ensure_ascii=False, indent=2))
    return 0


def cmd_pr_draft(args: argparse.Namespace) -> int:
    from trustchain.assistant.assistant import pr_draft

    data = json.loads(Path(args.report).read_text(encoding="utf-8"))
    req = Path(args.requirements)
    draft = pr_draft(data.get("findings", []), req.read_text(encoding="utf-8"), req.name)
    if draft is None:
        print("패치 버전이 있는 취약 의존성이 없습니다.")
        return 0
    print(f"# {draft['title']}\n\n{draft['body']}\n\n```diff\n{draft['diff']}```")
    if args.output:
        Path(args.output).write_text(json.dumps(draft, ensure_ascii=False, indent=2), encoding="utf-8")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="trustchain", description="TrustChain AI - SW 공급망 신뢰 검증·시큐어코딩 지원")
    p.add_argument("--version", action="version", version=f"trustchain {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    def common(sp: argparse.ArgumentParser, fmt: bool = True) -> None:
        sp.add_argument("--root", default=".", help="프로젝트 루트")
        sp.add_argument("--offline", action="store_true", help="네트워크 없이 캐시만 사용")
        if fmt:
            sp.add_argument("--format", choices=["text", "json", "sarif"], default="text")
            sp.add_argument("-o", "--output", help="결과 파일 경로")

    sp = sub.add_parser("check", help="커밋 전 시큐어코딩·패키지 점검 (pre-commit)")
    sp.add_argument("paths", nargs="*")
    sp.add_argument("--staged", action="store_true", help="git 스테이징된 파일만")
    sp.add_argument("--no-packages", action="store_true")
    sp.add_argument("--strict-packages", action="store_true", help="주의 판정 패키지도 실패로 처리")
    sp.add_argument("--no-external", action="store_true", help="Semgrep·Bandit 미사용")
    common(sp)
    sp.set_defaults(func=cmd_check)

    sp = sub.add_parser("pkg", help="패키지 설치 전 판정 (환각·타이포스쿼팅·신뢰 점수)")
    sp.add_argument("names", nargs="+")
    sp.add_argument("--version")
    sp.add_argument("--strict", action="store_true", help="주의 판정도 실패로 처리")
    sp.add_argument("--no-scorecard", action="store_true")
    common(sp)
    sp.set_defaults(func=cmd_pkg)

    sp = sub.add_parser("gate", help="빌드 보안 스캔 게이트")
    sp.add_argument("--image")
    sp.add_argument("--trivy-report")
    sp.add_argument("--stages", help="code,packages,models,docker,iac,image")
    sp.add_argument("--sarif")
    sp.add_argument("--no-external", action="store_true")
    common(sp)
    sp.set_defaults(func=cmd_gate)

    sp = sub.add_parser("scan-model", help="모델 파일 악성 pickle 스캔")
    sp.add_argument("path")
    common(sp)
    sp.set_defaults(func=cmd_scan_model)

    sp = sub.add_parser("sbom", help="CycloneDX SBOM 생성")
    sp.add_argument("-o", "--output", default="sbom.cdx.json")
    sp.add_argument("--name")
    sp.add_argument("--version", default="0.0.0")
    sp.add_argument("--image", help="이미지 대상 (Syft)")
    sp.add_argument("--no-syft", action="store_true")
    sp.add_argument("--from-env", action="store_true", help="설치된 패키지로 간접 의존성 보강")
    sp.add_argument("--with-aibom", action="store_true")
    common(sp, fmt=False)
    sp.set_defaults(func=cmd_sbom)

    sp = sub.add_parser("aibom", help="AI-BOM 생성")
    sp.add_argument("-o", "--output", default="aibom.cdx.json")
    sp.add_argument("--name")
    common(sp, fmt=False)
    sp.set_defaults(func=cmd_aibom)

    sp = sub.add_parser("aibom-verify", help="AI-BOM 해시와 실제 모델 파일 대조")
    sp.add_argument("aibom")
    sp.add_argument("--root", default=".")
    sp.set_defaults(func=cmd_aibom_verify)

    sp = sub.add_parser("verify", help="Verify Gate : 서명·출처 증명 검증")
    sp.add_argument("image")
    sp.add_argument("--repo", help="github.com/org/repo")
    sp.add_argument("--branch")
    sp.add_argument("--workflow", help="서명 주체 워크플로우 경로 (.github/workflows/x.yml)")
    sp.add_argument("--signer-repo", help="서명한 재사용 워크플로우 저장소 (기본: --repo)")
    sp.add_argument("--no-sbom", action="store_true")
    sp.add_argument("--require-aibom", action="store_true")
    sp.add_argument("--report-to", help="수집 API 주소")
    sp.add_argument("--service")
    common(sp)
    sp.set_defaults(func=cmd_verify)

    sp = sub.add_parser("iac", help="Kubernetes·Dockerfile·IaC 점검")
    sp.add_argument("path", nargs="?", default=".")
    sp.add_argument("--no-external", action="store_true")
    common(sp)
    sp.set_defaults(func=cmd_iac)

    sp = sub.add_parser("upload", help="수집 API 로 결과 전송 (TRUSTCHAIN_TOKEN)")
    sp.add_argument("kind", choices=["report", "sbom", "event"])
    sp.add_argument("--server", required=True)
    sp.add_argument("--service", required=True)
    sp.add_argument("--file")
    sp.add_argument("--repo")
    sp.add_argument("--image")
    sp.add_argument("--digest")
    sp.add_argument("--git-sha")
    sp.add_argument("--signed", action="store_true")
    sp.add_argument("--provenance", action="store_true")
    sp.add_argument("--stage", choices=["commit", "build", "deploy", "admission"], default="build")
    sp.add_argument("--passed", choices=["true", "false"], default="true")
    sp.add_argument("--reason")
    sp.set_defaults(func=cmd_upload)

    sp = sub.add_parser("server", help="수집 API 서버 실행")
    sp.add_argument("--host", default="127.0.0.1")
    sp.add_argument("--port", type=int, default=8000)
    sp.set_defaults(func=cmd_server)

    sp = sub.add_parser("token", help="API 토큰 발급")
    sp.add_argument("--name", required=True)
    sp.add_argument("--role", choices=["reader", "ingest", "admin"], required=True)
    sp.set_defaults(func=cmd_token)

    sp = sub.add_parser("feed", help="취약점 피드 1회 수집·매칭")
    sp.add_argument("--ecosystems")
    sp.add_argument("--max", type=int, default=500)
    sp.set_defaults(func=cmd_feed)

    sp = sub.add_parser("kb", help="지식베이스 적재")
    sp.add_argument("--osv-dir")
    sp.add_argument("--nvd-dir", help="NVD CVE API 2.0 응답 JSON 디렉터리")
    sp.add_argument("--cwe-csv")
    sp.add_argument("--offline-models", action="store_true", help="해싱 임베딩 사용")
    sp.set_defaults(func=cmd_kb)

    sp = sub.add_parser("ask", help="AI 보안 어시스턴트 질의")
    sp.add_argument("question")
    sp.add_argument("--report", help="gate 결과 JSON (우선순위 계산)")
    sp.add_argument("--root", help="실제 사용 여부 판단용 소스 루트")
    sp.add_argument("--top-k", type=int, default=5)
    sp.add_argument("--offline-models", action="store_true")
    sp.set_defaults(func=cmd_ask)

    sp = sub.add_parser("eval", help="RAG 검색·답변 품질 평가")
    sp.add_argument("--evalset", default="eval/rag_eval.jsonl")
    sp.add_argument("-k", type=int, default=5)
    sp.add_argument("--answers", action="store_true")
    sp.add_argument("--offline-models", action="store_true")
    sp.add_argument("--osv-dir", help="지식베이스에 추가할 OSV 덤프 디렉터리 (실제 운영 규모 측정)")
    sp.add_argument("--nvd-dir", help="지식베이스에 추가할 NVD CVE API 2.0 응답 JSON 디렉터리")
    sp.add_argument("--cwe-csv", help="지식베이스에 추가할 MITRE CWE CSV")
    sp.add_argument("-o", "--output")
    sp.set_defaults(func=cmd_eval)

    sp = sub.add_parser("model", help="패키지 위험 분류 모델 학습·평가 (real-data/eval-real: 실제 PyPI 데이터 검증)")
    sp.add_argument("action", choices=["train", "eval", "real-data", "eval-real"])
    sp.add_argument("--backend", choices=["linear", "keras"], default="linear")
    sp.add_argument("--out", help="모델 파일 (train/eval 기본 package_model.json, eval-real 기본 탑재 모델)")
    sp.add_argument("--seed", type=int, default=7)
    sp.add_argument("--data-dir", default="eval/pkg_real", help="실측 스냅샷 경로")
    sp.set_defaults(func=cmd_model)

    sp = sub.add_parser("pr-draft", help="취약 의존성 업그레이드 PR 초안")
    sp.add_argument("--report", required=True)
    sp.add_argument("--requirements", default="requirements.txt")
    sp.add_argument("-o", "--output")
    sp.set_defaults(func=cmd_pr_draft)
    return p


def main(argv: list[str] | None = None) -> int:
    _utf8()
    args = build_parser().parse_args(argv)
    try:
        return int(args.func(args) or 0)
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
