"""F10. 취약점 피드 모니터.

1) OSV 생태계별 modified_id.csv 로 마지막 확인 이후 변경된 취약점 ID 를 가져온다.
2) 각 취약점 상세를 받아 저장하고 (CVSS 없으면 NVD 로 보강),
3) 저장된 SBOM 구성요소와 버전 범위를 매칭해 영향받는 서비스를 찾고,
4) 신규 영향이면 Alert 를 만들고 Slack·메일로 즉시 알린다 (매칭→알림 지연 시간 기록).

SBOM 이 새로 수집될 때는 OSV querybatch 로 해당 아티팩트를 즉시 재검사한다.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version
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
# 최근 수정된 CVE (기간 최대 120일, ISO 8601). 페이지당 500건 (응답 크기 제한 20MB 이내)
NVD_RECENT = ("https://services.nvd.nist.gov/rest/json/cves/2.0?lastModStartDate={start}&lastModEndDate={end}"
              "&resultsPerPage=500&startIndex={index}")
DEFAULT_ECOSYSTEMS = ["PyPI", "Debian", "Alpine", "npm", "Go"]


@dataclass
class MonitorStats:
    fetched: int = 0
    matched: int = 0
    alerts: int = 0
    nvd_fetched: int = 0
    latencies_ms: list[float] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {"fetched": self.fetched, "nvd_fetched": self.nvd_fetched, "matched": self.matched, "alerts": self.alerts,
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


def _cpe_norm(name: str) -> str:
    return name.strip().lower().replace("_", "-").replace(".", "-")


def _cpe_product(m: dict[str, Any]) -> str:
    parts = (m.get("criteria") or "").split(":")
    return _cpe_norm(parts[4]) if len(parts) > 4 else ""


# CPE target_sw(대상 플랫폼) → SBOM 구성요소 생태계. 목록에 없는 플랫폼(wordpress·jenkins 등)은 우리 구성요소가 아니다
_TARGET_SW = {"python": "PyPI", "pypi": "PyPI", "node.js": "npm", "nodejs": "npm", "npm": "npm", "go": "Go",
              "golang": "Go", "rust": "crates.io", "ruby": "RubyGems", "java": "Maven", "maven": "Maven"}


def _same_version(a: str, b: str) -> bool:
    try:
        return Version(a) == Version(b)
    except InvalidVersion:
        return a == b


def cpe_affects(m: dict[str, Any], name: str, version: str, ecosystem: str | None = None) -> bool:
    """NVD cpeMatch 한 항목이 (구성요소 이름, 버전, 생태계)에 해당하는지.

    - 제품명은 대소문자·구분자(-, _, .)를 무시하고 비교
    - target_sw(예: python, node.js, wordpress)가 지정되어 있으면 구성요소 생태계와 일치해야 한다
      (WordPress·Jenkins 플러그인 CVE 가 같은 이름의 PyPI·npm 패키지에 알림으로 가지 않도록)
    - 범위 정보가 전혀 없으면 모든 버전으로 보지 않는다 (오탐 방지). PEP 440 이 아닌 버전(데비안 등)은 범위 비교를 하지 않는다
    """
    if _cpe_product(m) != _cpe_norm(name):
        return False
    parts = (m.get("criteria") or "").split(":")
    target = parts[10].lower() if len(parts) > 10 else "*"
    if target not in ("*", "-", ""):
        if _TARGET_SW.get(target) is None or (ecosystem is not None and _TARGET_SW[target] != ecosystem):
            return False
    exact = parts[5] if len(parts) > 5 else "*"
    if exact not in ("*", "-", ""):
        return _same_version(exact, version)
    try:
        v = Version(version)
        checks = [("versionStartIncluding", lambda b: v >= b), ("versionStartExcluding", lambda b: v > b),
                  ("versionEndIncluding", lambda b: v <= b), ("versionEndExcluding", lambda b: v < b)]
        bounded = False
        for key, ok in checks:
            if m.get(key):
                bounded = True
                if not ok(Version(m[key])):
                    return False
        return bounded
    except InvalidVersion:
        return False


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
        self._sleep = time.sleep  # NVD 공개 한도 대기 (테스트에서 교체)

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
            if os.environ.get("TRUSTCHAIN_NVD_FEED", "1") == "1":
                self.collect_nvd(s, stats)
                s.commit()
        return stats

    def collect_nvd(self, s: Session, stats: MonitorStats, now: datetime | None = None, max_pages: int = 10) -> None:
        """NVD 에서 마지막 수집 이후 수정된 CVE 를 받아 SBOM 구성요소와 CPE 로 매칭 (최초 실행은 최근 1일).

        한 번에 다 받지 못한 창(페이지 한도·조회 실패)은 진행 위치(nvd:cursor)를 남기고 다음 주기에 같은 창을 이어서 받는다.
        창을 끝까지 받은 뒤에만 기준 시각(nvd:since)을 옮긴다. API 키가 없으면 공개 한도(30초 5회)에 맞춰 페이지 사이에 대기한다.
        """
        now = now or datetime.now(timezone.utc)
        fmt = "%Y-%m-%dT%H:%M:%S.000Z"  # "+00:00" 의 + 는 URL 에서 공백이 되어 NVD 가 404
        cursor = json.loads(_get_state(s, "nvd:cursor") or "null")
        if cursor:
            start, end, index = (datetime.fromisoformat(cursor["start"]), datetime.fromisoformat(cursor["end"]),
                                 int(cursor["index"]))
        else:
            since = _get_state(s, "nvd:since")
            start, end, index = (datetime.fromisoformat(since) if since else now - timedelta(days=1)), now, 0
        start = max(start, end - timedelta(days=119))  # NVD API 기간 제한 120일
        headers = {"apiKey": self.nvd_key} if self.nvd_key else None
        covered = self._osv_covered_cves(s)
        comps = self._components_by_name(s)

        def save_cursor() -> None:
            _set_state(s, "nvd:cursor", json.dumps({"start": start.isoformat(), "end": end.isoformat(), "index": index}))

        for page in range(max_pages):
            if page:
                self._sleep(0.6 if self.nvd_key else 6.5)
            url = NVD_RECENT.format(start=start.strftime(fmt), end=end.strftime(fmt), index=index)
            try:
                data = self.http.get_json(url, headers=headers)
            except HttpError as e:
                log.warning("NVD 피드 조회 실패 (다음 주기에 이어서 받음): %s", e)
                save_cursor()
                return
            if not isinstance(data, dict):
                log.warning("NVD 응답 형식 오류 (다음 주기에 이어서 받음)")
                save_cursor()
                return
            items = data.get("vulnerabilities") or []
            for it in items:
                stats.nvd_fetched += 1
                self.process_nvd(s, it, stats, osv_aliases=covered, comps=comps)
            index += len(items)
            if not items or index >= int(data.get("totalResults") or 0):
                _set_state(s, "nvd:since", end.isoformat())
                _set_state(s, "nvd:cursor", "")
                return
        save_cursor()  # 페이지 한도 도달 : 남은 부분은 다음 주기에

    def _osv_covered_cves(self, s: Session) -> set[str]:
        """OSV 경로가 처리한 CVE (OSV 레코드의 별칭, 또는 id 자체가 CVE 인 OSV 레코드)."""
        covered: set[str] = set()
        for vid, aliases in s.execute(select(Vulnerability.id, Vulnerability.aliases)).all():
            covered.update(a for a in (aliases or []) if a.startswith("CVE-"))
            if vid.startswith("CVE-") and aliases:
                covered.add(vid)
        return covered

    def _components_by_name(self, s: Session) -> dict[str, list[Component]]:
        out: dict[str, list[Component]] = {}
        for c in s.scalars(select(Component).where(Component.type != "machine-learning-model")).all():
            if c.version:
                out.setdefault(_cpe_norm(c.name), []).append(c)
        return out

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
        ids = [v.id, *(v.aliases or [])]
        exists = s.scalar(select(Alert).where(Alert.service_id == svc.id, Alert.vuln_id.in_(ids),
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

    def process_nvd(self, s: Session, item: dict[str, Any], stats: MonitorStats | None = None,
                    osv_aliases: set[str] | None = None,
                    comps: dict[str, list[Component]] | None = None) -> list[Alert]:
        cve = item.get("cve") or {}
        cid = cve.get("id")
        if not cid:
            return []
        if osv_aliases is None:
            osv_aliases = self._osv_covered_cves(s)
        # OSV 에 같은 CVE 가 있으면 생태계·버전 정보가 정확한 OSV 경로가 처리한다
        if cid in osv_aliases:
            return []
        row = s.get(Vulnerability, cid)
        if row is not None and not (row.raw or {}).get("cve"):
            return []  # NVD 가 아닌 출처의 레코드는 덮어쓰지 않는다
        matches = [m for conf in cve.get("configurations", []) or [] for node in conf.get("nodes", []) or []
                   for m in node.get("cpeMatch", []) or [] if m.get("vulnerable")]
        products = {_cpe_product(m) for m in matches} - {""}
        if not products:
            return []
        if row is None:
            row = Vulnerability(id=cid)
            s.add(row)
        row.summary = next((d.get("value", "") for d in cve.get("descriptions", []) or [] if d.get("lang") == "en"), "")[:2000]
        row.aliases, row.modified, row.raw = [], cve.get("lastModified"), item
        for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30"):
            ms = (cve.get("metrics") or {}).get(key) or []
            if ms and (ms[0].get("cvssData") or {}).get("baseScore") is not None:
                row.cvss = float(ms[0]["cvssData"]["baseScore"])
                row.severity = severity_from_score(row.cvss).value
                break
        if comps is None:
            comps = self._components_by_name(s)
        created: list[Alert] = []
        for product in products:
            for c in comps.get(product, []):
                hits = [m for m in matches if cpe_affects(m, c.name, c.version, c.ecosystem)]
                if not hits:
                    continue
                if stats:
                    stats.matched += 1
                fixed = sorted({m["versionEndExcluding"] for m in hits if m.get("versionEndExcluding")})
                a = self._alert(s, c, row, fixed, stats)
                if a:
                    created.append(a)
        return created

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
