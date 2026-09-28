"""OSV(Open Source Vulnerabilities) API 클라이언트와 버전 범위 매칭."""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any

from packaging.version import InvalidVersion, Version

from trustchain.core.findings import Severity
from trustchain.core.http import CachedClient, HttpError

OSV_QUERY = "https://api.osv.dev/v1/query"
OSV_BATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/{id}"


@dataclass
class Vuln:
    id: str
    summary: str = ""
    details: str = ""
    aliases: list[str] = field(default_factory=list)
    severity: Severity = Severity.MEDIUM
    cvss_score: float | None = None
    fixed_versions: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    published: str | None = None
    modified: str | None = None
    raw: dict[str, Any] = field(default_factory=dict, repr=False)

    @property
    def cve(self) -> str | None:
        return next((a for a in [self.id, *self.aliases] if a.startswith("CVE-")), None)


def _cvss_base_score(vector: str) -> float | None:
    """CVSS v3.x 벡터 문자열에서 기본 점수 계산 (NVD 공식)."""
    try:
        parts = dict(p.split(":", 1) for p in vector.split("/")[1:])
    except ValueError:
        return None
    w = {
        "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
        "AC": {"L": 0.77, "H": 0.44},
        "UI": {"N": 0.85, "R": 0.62},
        "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    }
    try:
        scope_changed = parts["S"] == "C"
        pr = {"N": 0.85, "L": 0.68 if scope_changed else 0.62, "H": 0.5 if scope_changed else 0.27}[parts["PR"]]
        iss = 1 - (1 - w["C"][parts["C"]]) * (1 - w["C"][parts["I"]]) * (1 - w["C"][parts["A"]])
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if scope_changed else 6.42 * iss
        expl = 8.22 * w["AV"][parts["AV"]] * w["AC"][parts["AC"]] * pr * w["UI"][parts["UI"]]
    except KeyError:
        return None
    if impact <= 0:
        return 0.0
    raw = min(1.08 * (impact + expl), 10) if scope_changed else min(impact + expl, 10)


    return math.ceil(raw * 10 - 1e-9) / 10


def severity_from_score(score: float | None) -> Severity:
    if score is None:
        return Severity.MEDIUM
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0:
        return Severity.LOW
    return Severity.INFO


def parse_vuln(data: dict[str, Any], package: str | None = None) -> Vuln:
    score = None
    for s in data.get("severity", []) or []:
        if s.get("type", "").startswith("CVSS_V3"):
            score = _cvss_base_score(s.get("score", ""))
    sev = severity_from_score(score)
    if score is None:
        label = (data.get("database_specific") or {}).get("severity")
        if label:
            sev = Severity.parse(label)
    fixed: list[str] = []
    for aff in data.get("affected", []) or []:
        pkg = aff.get("package", {})
        if package and pkg.get("name", "").lower().replace("_", "-") != package.lower().replace("_", "-"):
            continue
        for r in aff.get("ranges", []) or []:
            for ev in r.get("events", []):
                if "fixed" in ev:
                    fixed.append(ev["fixed"])
    return Vuln(
        id=data.get("id", ""),
        summary=data.get("summary", "") or "",
        details=data.get("details", "") or "",
        aliases=data.get("aliases", []) or [],
        severity=sev,
        cvss_score=score,
        fixed_versions=sorted(set(fixed), key=_vkey),
        references=[r.get("url") for r in data.get("references", []) or [] if r.get("url")],
        published=data.get("published"),
        modified=data.get("modified"),
        raw=data,
    )


def _vkey(v: str):
    try:
        return (0, Version(v))
    except InvalidVersion:
        return (1, v)


def is_affected(data: dict[str, Any], package: str, version: str, ecosystem: str = "PyPI") -> bool:
    """OSV affected[] 의 versions 목록과 ECOSYSTEM/SEMVER 범위로 영향 여부 판정."""
    norm = package.lower().replace("_", "-").replace(".", "-")
    try:
        v = Version(version)
    except InvalidVersion:
        v = None
    for aff in data.get("affected", []) or []:
        pkg = aff.get("package", {})
        if pkg.get("ecosystem") != ecosystem:
            continue
        if pkg.get("name", "").lower().replace("_", "-").replace(".", "-") != norm:
            continue
        if version in (aff.get("versions") or []):
            return True
        if v is None:
            continue
        for r in aff.get("ranges", []) or []:
            if r.get("type") not in ("ECOSYSTEM", "SEMVER"):
                continue
            # events 는 introduced / fixed / last_affected 를 시간순으로 나열
            events = sorted(
                r.get("events", []),
                key=lambda e: _vkey(next(iter(e.values()))) if next(iter(e.values())) != "0" else (-1, ""),
            )
            affected = False
            for ev in events:
                try:
                    if "introduced" in ev:
                        if ev["introduced"] == "0" or v >= Version(ev["introduced"]):
                            affected = True
                    elif "fixed" in ev:
                        if v >= Version(ev["fixed"]):
                            affected = False
                    elif "last_affected" in ev:
                        if v > Version(ev["last_affected"]):
                            affected = False
                except InvalidVersion:
                    continue
            if affected:
                return True
    return False


class OSVClient:
    def __init__(self, http: CachedClient):
        self.http = http

    def query(self, name: str, version: str | None, ecosystem: str = "PyPI") -> list[Vuln]:
        payload: dict[str, Any] = {"package": {"name": name, "ecosystem": ecosystem}}
        if version:
            payload["version"] = version
        try:
            data = self.http.post_json(OSV_QUERY, payload)
        except HttpError:
            return []
        return [parse_vuln(v, name) for v in data.get("vulns", []) or []]

    def query_batch(self, items: list[tuple[str, str]], ecosystem: str = "PyPI") -> dict[tuple[str, str], list[str]]:
        """(이름, 버전) 목록 → 취약점 ID 목록. 상세는 get_vuln 으로 조회."""
        out: dict[tuple[str, str], list[str]] = {}
        for i in range(0, len(items), 500):
            chunk = items[i : i + 500]
            payload = {"queries": [{"package": {"name": n, "ecosystem": ecosystem}, "version": v} for n, v in chunk]}
            try:
                data = self.http.post_json(OSV_BATCH, payload)
            except HttpError:
                continue
            for (n, v), res in zip(chunk, data.get("results", [])):
                out[(n, v)] = [x["id"] for x in res.get("vulns", []) or []]
        return out

    def get_vuln(self, vid: str) -> dict[str, Any] | None:
        try:
            data = self.http.get_json(OSV_VULN.format(id=vid))
        except HttpError:
            return None
        return None if data.get("__status__") == 404 else data
