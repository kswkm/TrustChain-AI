"""F10. 취약점 피드 모니터.

1) OSV 생태계별 modified_id.csv 로 마지막 확인 이후 변경된 취약점 ID 를 가져온다.
2) 각 취약점 상세를 받아 저장하고 (CVSS 없으면 NVD 로 보강),
3) 저장된 SBOM 구성요소와 버전 범위를 매칭해 영향받는 서비스를 찾고,
4) 신규 영향이면 Alert 를 만들고 Slack·메일로 즉시 알린다 (매칭→알림 지연 시간 기록).

SBOM 이 새로 수집될 때는 OSV querybatch 로 해당 아티팩트를 즉시 재검사한다.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from packaging.utils import canonicalize_name
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from trustchain.core.http import CachedClient, HttpError
from trustchain.core.logging import get_logger
from trustchain.feed.notify import AlertMessage, Notifier
from trustchain.packages.osv import OSVClient, is_affected, parse_vuln, severity_from_score
from trustchain.server.db import Alert, Artifact, Component, FeedState, Service, Vulnerability, utcnow

log = get_logger("trustchain.feed")
OSV_MODIFIED = "https://osv-vulnerabilities.storage.googleapis.com/{eco}/modified_id.csv"
NVD_CVE = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}"
DEFAULT_ECOSYSTEMS = ["PyPI", "Debian", "Alpine", "npm", "Go"]


@dataclass
class MonitorStats:
    fetched: int = 0
    matched: int = 0
    alerts: int = 0
    latencies_ms: list[float] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {"fetched": self.fetched, "matched": self.matched, "alerts": self.alerts,
                "max_alert_latency_ms": round(max(self.latencies_ms), 1) if self.latencies_ms else None}


def _norm(name: str, eco: str | None) -> str:
    return canonicalize_name(name) if eco == "PyPI" else name.lower()


def _get_state(s: Session, key: str) -> str | None:
    row = s.get(FeedState, key)
    return row.value if row else None


def _set_state(s: Session, key: str, value: str) -> None:
    row = s.get(FeedState, key)
    if row:
        row.value = value
    else:
        s.add(FeedState(key=key, value=value))


def parse_modified_csv(text: str, since: str | None, limit: int = 2000) -> list[tuple[str, str]]:
    """'<RFC3339 수정시각>,<ID>' 목록(최신순) → since 이후 항목."""
    out = []
    for line in text.splitlines():
        if "," not in line:
            continue
        ts, vid = line.split(",", 1)
        ts, vid = ts.strip(), vid.strip()
        if since and ts <= since:
            break
        out.append((ts, vid))
        if len(out) >= limit:
            break
    return out


class FeedMonitor:
    def __init__(self, session_factory, notifier: Notifier, http: CachedClient | None = None,
                 ecosystems: list[str] | None = None):
        self.sf = session_factory
        self.notifier = notifier
        self.http = http or CachedClient(ttl=0)
        self.osv = OSVClient(self.http)
        self.ecosystems = ecosystems or DEFAULT_ECOSYSTEMS
        self.nvd_key = os.environ.get("NVD_API_KEY")
        self.nvd_enrich = bool(self.nvd_key) or os.environ.get("TRUSTCHAIN_NVD_ENRICH") == "1"

    # ---- 수집 ----
    def run_once(self, max_per_ecosystem: int = 500) -> MonitorStats:
        stats = MonitorStats()
        with self.sf() as s:
            for eco in self.ecosystems:
                key = f"osv:{eco}:since"
                since = _get_state(s, key)
                try:
                    text = self.http.get_text(OSV_MODIFIED.format(eco=eco), max_bytes=2 * 1024 * 1024)
                except HttpError as e:
                    log.warning("OSV 피드 조회 실패 %s: %s", eco, e)
                    continue
                items = parse_modified_csv(text, since, max_per_ecosystem)
                if since is None:
                    # 최초 실행 : 최근 항목만 처리하고 기준점을 잡는다
                    items = items[:50]
                for _ts, vid in items:
                    data = self.osv.get_vuln(vid)
                    if not data:
                        continue
                    stats.fetched += 1
                    self.process_vuln(s, data, stats)
                if items:
                    _set_state(s, key, items[0][0])
                s.commit()
        return stats

    def enrich_nvd(self, v: Vulnerability) -> None:
        cve = next((a for a in [v.id, *(v.aliases or [])] if a.startswith("CVE-")), None)
        if not cve or v.cvss is not None:
            return
        try:
            data = self.http.get_json(NVD_CVE.format(cve=cve),
                                      headers={"apiKey": self.nvd_key} if self.nvd_key else None)
        except HttpError:
            return
        for item in data.get("vulnerabilities", []) or []:
            metrics = (item.get("cve") or {}).get("metrics") or {}
            for k in ("cvssMetricV31", "cvssMetricV30"):
                for m in metrics.get(k, []) or []:
                    score = (m.get("cvssData") or {}).get("baseScore")
                    if score is not None:
                        v.cvss = float(score)
                        v.severity = severity_from_score(v.cvss).value
                        return

    # ---- 매칭 ----
    def process_vuln(self, s: Session, data: dict[str, Any], stats: MonitorStats | None = None) -> list[Alert]:
        vu = parse_vuln(data)
        row = s.get(Vulnerability, vu.id)
        if row is None:
            row = Vulnerability(id=vu.id)
            s.add(row)
        row.summary, row.severity, row.cvss = vu.summary or vu.details[:300], vu.severity.value, vu.cvss_score
        row.aliases, row.modified, row.raw = vu.aliases, vu.modified, data
        if row.cvss is None and self.nvd_enrich:
            self.enrich_nvd(row)
        created: list[Alert] = []
        for aff in data.get("affected", []) or []:
            pkg = aff.get("package") or {}
            eco_full = pkg.get("ecosystem", "")
            eco = eco_full.split(":")[0]
            name = pkg.get("name")
            if not name:
                continue
            cname = canonicalize_name(name) if eco == "PyPI" else name.lower()
            cands = s.scalars(select(Component).where(Component.ecosystem == eco,
                                                      func.lower(Component.name) == cname)).all()
            for c in cands:
                if _norm(c.name, eco) != _norm(name, eco) or not c.version:
                    continue
                if not is_affected({"affected": [{**aff, "package": {**pkg, "ecosystem": eco}}]}, name, c.version,
                                   eco):
                    continue
                if stats:
                    stats.matched += 1
                a = self._alert(s, c, row, vu.fixed_versions, stats)
                if a:
                    created.append(a)
        return created

    def _alert(self, s: Session, c: Component, v: Vulnerability, fixed: list[str],
               stats: MonitorStats | None) -> Alert | None:
        art = s.get(Artifact, c.artifact_id)
        svc = s.get(Service, art.service_id) if art else None
        if svc is None:
            return None
        exists = s.scalar(select(Alert).where(Alert.service_id == svc.id, Alert.vuln_id == v.id,
                                              Alert.component == c.name, Alert.version == c.version))
        if exists:
            return None
        t0 = time.perf_counter()
        a = Alert(service_id=svc.id, vuln_id=v.id, component=c.name, version=c.version, severity=v.severity,
                  fixed_versions=fixed, matched_at=utcnow())
        s.add(a)
        try:
            s.flush()
        except IntegrityError:
            s.rollback()
            return None
        msg = AlertMessage(svc.name, v.id, v.severity, c.name, c.version, v.summary or "", fixed,
                           [x.strip() for x in (svc.owner_contact or "").split(",") if x.strip()])
        if self.notifier.send(msg):
            a.notified_at = datetime.now(timezone.utc)
        latency = (time.perf_counter() - t0) * 1000
        if stats:
            stats.alerts += 1
            stats.latencies_ms.append(latency)
        log.info("알림: %s %s %s %s (%.1fms)", svc.name, v.id, c.name, c.version, latency)
        return a

    def match_artifact(self, artifact_id: int) -> MonitorStats:
        """새로 수집된 SBOM 을 OSV querybatch 로 즉시 검사."""
        stats = MonitorStats()
        with self.sf() as s:
            comps = s.scalars(select(Component).where(Component.artifact_id == artifact_id)).all()
            by_eco: dict[str, list[Component]] = {}
            for c in comps:
                if c.ecosystem and c.version and c.type != "machine-learning-model":
                    by_eco.setdefault(c.ecosystem, []).append(c)
            for eco, items in by_eco.items():
                res = self.osv.query_batch([(c.name, c.version) for c in items], eco)  # type: ignore[misc]
                for c in items:
                    for vid in res.get((c.name, c.version), []):  # type: ignore[arg-type]
                        data = self.osv.get_vuln(vid)
                        if not data:
                            continue
                        stats.fetched += 1
                        self.process_vuln(s, data, stats)
            s.commit()
        return stats


def start_scheduler(monitor: FeedMonitor, minutes: int = 10):
    """APScheduler 로 주기 수집 (서버 프로세스에서 호출)."""
    from apscheduler.schedulers.background import BackgroundScheduler

    sched = BackgroundScheduler(timezone="UTC")
    sched.add_job(monitor.run_once, "interval", minutes=minutes, id="osv-feed", max_instances=1, coalesce=True,
                  next_run_time=datetime.now(timezone.utc))
    sched.start()
    return sched
