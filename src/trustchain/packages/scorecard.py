"""OpenSSF Scorecard API 클라이언트."""

from __future__ import annotations

from trustchain.core.http import CachedClient, HttpError

SCORECARD_URL = "https://api.securityscorecards.dev/projects/{repo}"


class ScorecardClient:
    def __init__(self, http: CachedClient):
        self.http = http

    def score(self, repo: str | None) -> float | None:
        """repo: 'github.com/owner/name'. 0~10 점수, 없으면 None."""
        if not repo:
            return None
        try:
            data = self.http.get_json(SCORECARD_URL.format(repo=repo))
        except HttpError:
            return None
        if data.get("__status__") == 404:
            return None
        s = data.get("score")
        return float(s) if isinstance(s, (int, float)) else None
