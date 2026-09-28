"""외부 API 호출용 HTTP 클라이언트 : 타임아웃, 응답 크기 제한, 디스크 캐시."""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any

import httpx

from trustchain import __version__

DEFAULT_TIMEOUT = httpx.Timeout(10.0, connect=5.0)
MAX_BYTES = 20 * 1024 * 1024
USER_AGENT = f"trustchain-ai/{__version__} (+https://github.com/kswkm/TrustChain-AI)"


class HttpError(RuntimeError):
    pass


class CachedClient:
    """GET/POST JSON 응답을 TTL 기반으로 캐시한다. 캐시는 JSON 으로만 저장한다 (pickle 미사용)."""

    def __init__(self, cache_dir: Path | None = None, ttl: int = 6 * 3600, offline: bool = False):
        self.cache_dir = cache_dir
        self.ttl = ttl
        self.offline = offline
        self._client = httpx.Client(
            timeout=DEFAULT_TIMEOUT, headers={"User-Agent": USER_AGENT}, follow_redirects=True, verify=True
        )

    def _cache_path(self, key: str) -> Path | None:
        if not self.cache_dir:
            return None
        h = hashlib.sha256(key.encode()).hexdigest()
        return self.cache_dir / "http" / h[:2] / f"{h}.json"

    def _read_cache(self, key: str, ignore_ttl: bool = False) -> Any | None:
        p = self._cache_path(key)
        if not p or not p.is_file():
            return None
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        if not ignore_ttl and time.time() - data.get("ts", 0) > self.ttl:
            return None
        return data.get("body")

    def _write_cache(self, key: str, body: Any) -> None:
        p = self._cache_path(key)
        if not p:
            return
        try:
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(json.dumps({"ts": time.time(), "body": body}), encoding="utf-8")
        except OSError:
            pass

    def _request(self, method: str, url: str, **kw: Any) -> Any:
        key = method + " " + url + " " + json.dumps(kw.get("json"), sort_keys=True)
        cached = self._read_cache(key, ignore_ttl=self.offline)
        if cached is not None:
            return cached
        if self.offline:
            raise HttpError(f"offline 모드: 캐시 없음 ({url})")
        try:
            with self._client.stream(method, url, **kw) as r:
                chunks, size = [], 0
                for c in r.iter_bytes():
                    size += len(c)
                    if size > MAX_BYTES:
                        raise HttpError(f"응답이 너무 큽니다: {url}")
                    chunks.append(c)
                raw = b"".join(chunks)
                if r.status_code == 404:
                    body: Any = {"__status__": 404}
                elif r.status_code >= 400:
                    raise HttpError(f"HTTP {r.status_code}: {url}")
                else:
                    body = json.loads(raw) if raw else {}
        except httpx.HTTPError as e:
            stale = self._read_cache(key, ignore_ttl=True)
            if stale is not None:
                return stale
            raise HttpError(f"요청 실패: {url} ({e.__class__.__name__})") from e
        self._write_cache(key, body)
        return body

    def get_json(self, url: str, **kw: Any) -> Any:
        return self._request("GET", url, **kw)

    def post_json(self, url: str, payload: Any, **kw: Any) -> Any:
        return self._request("POST", url, json=payload, **kw)

    def get_text(self, url: str, max_bytes: int = MAX_BYTES) -> str:
        """캐시하지 않는 텍스트 GET (피드 목록 등 자주 바뀌는 자원)."""
        if self.offline:
            raise HttpError(f"offline 모드: {url}")
        try:
            with self._client.stream("GET", url) as r:
                if r.status_code >= 400:
                    raise HttpError(f"HTTP {r.status_code}: {url}")
                chunks, size = [], 0
                for c in r.iter_bytes():
                    size += len(c)
                    if size > max_bytes:
                        break  # 앞부분(최신 항목)만 필요
                    chunks.append(c)
        except httpx.HTTPError as e:
            raise HttpError(f"요청 실패: {url} ({e.__class__.__name__})") from e
        return b"".join(chunks).decode("utf-8", "replace")

    def post(self, url: str, payload: Any, headers: dict[str, str] | None = None) -> int:
        """캐시하지 않는 POST (알림 전송). 상태 코드 반환."""
        try:
            r = self._client.post(url, json=payload, headers=headers or {})
        except httpx.HTTPError as e:
            raise HttpError(f"요청 실패 ({e.__class__.__name__})") from e
        return r.status_code

    def close(self) -> None:
        self._client.close()
