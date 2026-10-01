"""GitHub REST API 클라이언트 : 저장소 유지관리 활동(보관 여부·최근 push) 조회 (F4 신뢰 점수).

토큰 없이도 동작한다(비인증 한도 60회/시간). GITHUB_TOKEN 또는 TRUSTCHAIN_GITHUB_TOKEN 이 있으면 사용한다.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import datetime

from trustchain.core.http import CachedClient, HttpError

GITHUB_REPO_URL = "https://api.github.com/repos/{owner}/{name}"


@dataclass
class RepoActivity:
    archived: bool
    pushed_at: datetime | None


class GitHubClient:
    def __init__(self, http: CachedClient, token: str | None = None):
        self.http = http
        self.token = token if token is not None else (
            os.environ.get("TRUSTCHAIN_GITHUB_TOKEN") or os.environ.get("GITHUB_TOKEN"))

    def repo_activity(self, repo: str | None) -> RepoActivity | None:
        """repo: 'github.com/owner/name'. 조회할 수 없으면 None (점수에서 해당 항목만 제외)."""
        if not repo or not repo.startswith("github.com/") or repo.count("/") != 2:
            return None
        _, owner, name = repo.split("/")
        headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        try:
            data = self.http.get_json(GITHUB_REPO_URL.format(owner=owner, name=name), headers=headers)
        except HttpError:
            return None
        if not isinstance(data, dict) or data.get("__status__") == 404 or "archived" not in data:
            return None
        pushed = data.get("pushed_at")
        try:
            pushed_at = datetime.fromisoformat(pushed.replace("Z", "+00:00")) if pushed else None
        except ValueError:
            pushed_at = None
        return RepoActivity(bool(data.get("archived")), pushed_at)
