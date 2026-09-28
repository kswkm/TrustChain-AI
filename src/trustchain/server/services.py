"""수집 API 비즈니스 로직 : 리포트·SBOM 저장, 서비스 신뢰 점수 계산."""

from __future__ import annotations

from typing import Any

from packaging.utils import canonicalize_name
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from trustchain.bom.sbom import components_from_sbom
from trustchain.server.db import Alert, Artifact, Component, GateEvent, ScanReport, Service
from trustchain.server.schemas import EventIn, ReportIn, SBOMIn

SEVERITY_PENALTY = {"CRITICAL": 25, "HIGH": 10, "MEDIUM": 3, "LOW": 1, "INFO": 0}


def get_or_create_service(s: Session, name: str, repo: str | None = None) -> Service:
    svc = s.scalar(select(Service).where(Service.name == name))
    if svc is None:
        svc = Service(name=name, repo=repo)
        s.add(svc)
        s.flush()
    elif repo and not svc.repo:
        svc.repo = repo
    return svc


def get_or_create_artifact(s: Session, svc: Service, digest: str | None, image: str | None,
                           git_sha: str | None) -> Artifact | None:
    if not digest:
        return None
    art = s.scalar(select(Artifact).where(Artifact.service_id == svc.id, Artifact.digest == digest))
    if art is None:
        art = Artifact(service_id=svc.id, digest=digest, image=image, git_sha=git_sha)
        s.add(art)
        s.flush()
    return art


def ingest_report(s: Session, body: ReportIn) -> ScanReport:
    svc = get_or_create_service(s, body.service, body.repo)
    art = get_or_create_artifact(s, svc, body.digest, body.image, body.git_sha)
    if art is not None:
        art.signed = art.signed or body.signed
        art.provenance = art.provenance or body.provenance
    rep = ScanReport(
        service_id=svc.id, artifact_id=art.id if art else None, passed=body.passed,
        summary={**body.summary, "violations": body.violations},  # type: ignore[dict-item]
        findings=[f.model_dump() for f in body.findings],
    )
    s.add(rep)
    s.add(GateEvent(service_id=svc.id, stage="build", image=body.image, passed=body.passed,
                    reason="; ".join(body.violations)[:4000]))
    s.commit()
    return rep


def ingest_sbom(s: Session, body: SBOMIn) -> tuple[Artifact, int]:
    svc = get_or_create_service(s, body.service)
    digest = body.digest or f"sha256:{'0' * 64}"
    art = get_or_create_artifact(s, svc, digest, body.image, body.git_sha)
    assert art is not None
    # 같은 아티팩트의 SBOM 은 교체
    for c in list(art.components):
        s.delete(c)
    s.flush()
    comps = components_from_sbom(body.sbom)
    for c in comps:
        if not c.get("name"):
            continue
        name = canonicalize_name(c["name"]) if c.get("ecosystem") == "PyPI" else str(c["name"])
        s.add(Component(
            artifact_id=art.id, name=name[:256], version=(c.get("version") or None) and str(c["version"])[:128],
            purl=(c.get("purl") or None) and str(c["purl"])[:512], ecosystem=(c.get("ecosystem") or None) and
            str(c["ecosystem"])[:32], type=str(c.get("type") or "library")[:32], sha256=c.get("sha256"),
        ))
    s.commit()
    return art, len(comps)


def record_event(s: Session, body: EventIn) -> GateEvent:
    svc = get_or_create_service(s, body.service)
    ev = GateEvent(service_id=svc.id, stage=body.stage, image=body.image, passed=body.passed, reason=body.reason)
    s.add(ev)
    # Verify Gate 를 통과해 배포되었다면 서명·출처 증명이 검증된 것이다
    if body.stage == "deploy" and body.passed and body.image and "@" in body.image:
        digest = body.image.split("@", 1)[1]
        art = s.scalar(select(Artifact).where(Artifact.service_id == svc.id, Artifact.digest == digest))
        if art:
            art.deployed = True
            art.signed = True
            art.provenance = True
    s.commit()
    return ev


def latest_artifact(s: Session, svc: Service) -> Artifact | None:
    return s.scalar(select(Artifact).where(Artifact.service_id == svc.id)
                    .order_by(Artifact.deployed.desc(), Artifact.created_at.desc(), Artifact.id.desc()).limit(1))


def service_trust_score(s: Session, svc: Service) -> tuple[int, dict[str, Any]]:
    """서비스 신뢰 점수 (0~100) 와 감점 내역."""
    detail: dict[str, Any] = {}
    score = 100
    rep = s.scalar(select(ScanReport).where(ScanReport.service_id == svc.id)
                   .order_by(ScanReport.created_at.desc(), ScanReport.id.desc()).limit(1))
    if rep is None:
        return 0, {"reason": "스캔 이력 없음"}
    pen = sum(SEVERITY_PENALTY.get(k, 0) * int(v) for k, v in rep.summary.items() if k in SEVERITY_PENALTY)
    pen = min(pen, 50)
    score -= pen
    detail["findings_penalty"] = pen
    art = latest_artifact(s, svc)
    if art is None or not art.signed:
        score -= 20
        detail["unsigned"] = -20
    if art is None or not art.provenance:
        score -= 15
        detail["no_provenance"] = -15
    alerts = s.scalars(select(Alert).where(Alert.service_id == svc.id, Alert.resolved.is_(False))).all()
    ap = min(sum(SEVERITY_PENALTY.get(a.severity, 0) for a in alerts), 30)
    score -= ap
    detail["alerts_penalty"] = ap
    return max(0, score), detail


def list_services(s: Session) -> list[dict[str, Any]]:
    out = []
    for svc in s.scalars(select(Service).order_by(Service.name)).all():
        score, detail = service_trust_score(s, svc)
        art = latest_artifact(s, svc)
        n_comp = s.scalar(select(func.count(Component.id)).where(Component.artifact_id == art.id)) if art else 0
        open_alerts = s.scalar(select(func.count(Alert.id)).where(Alert.service_id == svc.id,
                                                                 Alert.resolved.is_(False))) or 0
        last = s.scalar(select(GateEvent).where(GateEvent.service_id == svc.id)
                        .order_by(GateEvent.created_at.desc(), GateEvent.id.desc()).limit(1))
        out.append({
            "name": svc.name, "repo": svc.repo, "trust_score": score, "score_detail": detail,
            "latest_digest": art.digest if art else None, "components": n_comp or 0, "open_alerts": open_alerts,
            "last_gate_passed": last.passed if last else None,
        })
    return out


def service_components(s: Session, name: str, q: str | None = None, limit: int = 500) -> list[dict[str, Any]]:
    svc = s.scalar(select(Service).where(Service.name == name))
    if svc is None:
        return []
    art = latest_artifact(s, svc)
    if art is None:
        return []
    stmt = select(Component).where(Component.artifact_id == art.id)
    if q:
        stmt = stmt.where(Component.name.ilike(f"%{q.replace('%', '').replace('_', '')}%"))
    rows = s.scalars(stmt.order_by(Component.name).limit(limit)).all()
    return [{"name": c.name, "version": c.version, "purl": c.purl, "ecosystem": c.ecosystem, "type": c.type,
             "sha256": c.sha256} for c in rows]


def latest_findings(s: Session, name: str) -> list[dict[str, Any]]:
    svc = s.scalar(select(Service).where(Service.name == name))
    if svc is None:
        return []
    rep = s.scalar(select(ScanReport).where(ScanReport.service_id == svc.id)
                   .order_by(ScanReport.created_at.desc(), ScanReport.id.desc()).limit(1))
    return list(rep.findings) if rep else []
