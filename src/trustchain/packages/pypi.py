"""PyPI JSON API 클라이언트 → 판정에 쓰는 메타데이터 요약."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Protocol

from packaging.utils import canonicalize_name

from trustchain.core.http import CachedClient, HttpError

PYPI_URL = "https://pypi.org/pypi/{name}/json"


@dataclass
class PackageMeta:
    name: str
    exists: bool
    latest_version: str | None = None
    first_release: datetime | None = None
    last_release: datetime | None = None
    release_count: int = 0
    maintainer_count: int = 0
    description_len: int = 0
    summary: str = ""
    has_wheel: bool = True  # 휠이 없으면 설치 시 setup.py(설치 스크립트)가 실행된다
    home_page: str | None = None
    repository: str | None = None  # github.com/owner/repo
    yanked_latest: bool = False
    known_vulns: list[str] = field(default_factory=list)  # PyPI 가 알려주는 최신 버전 취약점 ID
    lookup_error: str | None = None

    def age_days(self, now: datetime | None = None) -> float | None:
        if not self.first_release:
            return None
        now = now or datetime.now(timezone.utc)
        return (now - self.first_release).total_seconds() / 86400

    def days_since_release(self, now: datetime | None = None) -> float | None:
        if not self.last_release:
            return None
        now = now or datetime.now(timezone.utc)
        return (now - self.last_release).total_seconds() / 86400


class MetaSource(Protocol):
    def get(self, name: str) -> PackageMeta: ...


_GH = re.compile(r"github\.com[/:]([A-Za-z0-9_.\-]+)/([A-Za-z0-9_.\-]+?)(?:\.git)?(?:[/#?]|$)")


def find_github_repo(info: dict[str, Any]) -> str | None:
    urls = list((info.get("project_urls") or {}).values()) + [info.get("home_page") or ""]
    for u in urls:
        m = _GH.search(u or "")
        if m and m.group(1).lower() not in ("sponsors", "orgs"):
            return f"github.com/{m.group(1)}/{m.group(2)}"
    return None


def _parse_time(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None


def meta_from_json(name: str, data: dict[str, Any]) -> PackageMeta:
    if not data or data.get("__status__") == 404:
        return PackageMeta(name=canonicalize_name(name), exists=False)
    info = data.get("info", {})
    releases = data.get("releases", {}) or {}
    times: list[datetime] = []
    for files in releases.values():
        for f in files or []:
            t = _parse_time(f.get("upload_time_iso_8601"))
            if t:
                times.append(t)
    people = {
        x.strip().lower()
        for x in (info.get("author"), info.get("maintainer"), info.get("author_email"), info.get("maintainer_email"))
        if x and x.strip()
    }
    # 이메일 필드에는 쉼표로 여러 명이 들어갈 수 있다
    expanded: set[str] = set()
    for p in people:
        expanded.update(s.strip() for s in p.split(",") if s.strip())
    urls = data.get("urls", []) or []
    return PackageMeta(
        name=canonicalize_name(info.get("name") or name),
        exists=True,
        latest_version=info.get("version"),
        first_release=min(times) if times else None,
        last_release=max(times) if times else None,
        release_count=sum(1 for v in releases.values() if v),
        maintainer_count=max(1, len({e.split("<")[-1].strip(">") for e in expanded})) if expanded else 0,
        description_len=len(info.get("description") or ""),
        summary=info.get("summary") or "",
        has_wheel=any(u.get("packagetype") == "bdist_wheel" for u in urls) if urls else False,
        home_page=info.get("home_page"),
        repository=find_github_repo(info),
        yanked_latest=bool(info.get("yanked")),
        known_vulns=[v.get("id") for v in data.get("vulnerabilities", []) or [] if v.get("id")],
    )


class PyPIClient:
    def __init__(self, http: CachedClient):
        self.http = http

    def get(self, name: str) -> PackageMeta:
        try:
            data = self.http.get_json(PYPI_URL.format(name=canonicalize_name(name)))
        except HttpError as e:
            return PackageMeta(name=canonicalize_name(name), exists=True, lookup_error=str(e))
        return meta_from_json(name, data)
