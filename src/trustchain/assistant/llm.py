"""F11-5. LLM API 클라이언트.

- anthropic : Claude Messages API (기본 모델 claude-sonnet-5-5)
- openai    : OpenAI 호환 Chat Completions API (사내 게이트웨이·로컬 LLM 서버)
- extractive: LLM 없이 근거 문서 문장을 발췌해 답변 (오프라인·테스트)
API 키는 환경변수(TRUSTCHAIN_LLM_API_KEY / ANTHROPIC_API_KEY)에서만 읽는다.
"""

from __future__ import annotations

import os
import re
from typing import Protocol

import httpx

from trustchain.assistant.text import tokenize


class LLM(Protocol):
    def complete(self, system: str, user: str, max_tokens: int = 1200) -> str: ...


class AnthropicLLM:
    URL = "https://api.anthropic.com/v1/messages"

    def __init__(self, api_key: str, model: str | None = None):
        self.api_key = api_key
        self.model = model or os.environ.get("TRUSTCHAIN_LLM_MODEL", "claude-sonnet-5-5")

    def complete(self, system: str, user: str, max_tokens: int = 1200) -> str:
        # Sonnet 5 계열은 사고(thinking)가 기본으로 켜져 있어 그 토큰도 max_tokens 에 포함된다 → 본문이 잘리지 않도록 여유를 둔다.
        # temperature 등 샘플링 파라미터는 400 오류가 나므로 보내지 않는다.
        r = httpx.post(
            self.URL,
            headers={"x-api-key": self.api_key, "anthropic-version": "2023-06-01", "content-type": "application/json"},
            json={"model": self.model, "max_tokens": max(max_tokens, 16000), "system": system,
                  "messages": [{"role": "user", "content": user}]},
            timeout=120,
        )
        r.raise_for_status()
        return "".join(b.get("text", "") for b in r.json().get("content", []) if b.get("type") == "text")


class OpenAICompatLLM:
    def __init__(self, api_key: str, base_url: str, model: str):
        self.api_key, self.base_url, self.model = api_key, base_url.rstrip("/"), model

    def complete(self, system: str, user: str, max_tokens: int = 1200) -> str:
        r = httpx.post(
            f"{self.base_url}/chat/completions",
            headers={"Authorization": f"Bearer {self.api_key}"},
            json={"model": self.model, "max_tokens": max_tokens, "temperature": 0,
                  "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}]},
            timeout=60,
        )
        r.raise_for_status()
        return r.json()["choices"][0]["message"]["content"]


class ExtractiveLLM:
    """근거 문서에서 질문과 가장 관련 있는 문장을 인용 번호와 함께 발췌한다."""

    def complete(self, system: str, user: str, max_tokens: int = 1200) -> str:
        docs = re.findall(r'<document index="(\d+)"[^>]*>(.*?)</document>', user, re.S)
        qm = re.search(r"<question>(.*?)</question>", user, re.S)
        q = set(tokenize(qm.group(1) if qm else ""))
        if not docs or not q:
            return "제공된 근거 문서에서 답을 찾을 수 없습니다."
        cands = []
        for idx, body in docs:
            for sent in re.split(r"(?<=[.!?。])\s+|\n+", body):
                sent = sent.strip()
                if len(sent) < 8:
                    continue
                ov = len(q & set(tokenize(sent)))
                if ov:
                    cands.append((ov, int(idx), sent))
        if not cands:
            return "제공된 근거 문서에서 답을 찾을 수 없습니다."
        cands.sort(key=lambda t: (-t[0], t[1]))
        best = cands[0][0]
        lines, seen = [], set()
        for ov, idx, sent in cands:
            # 질문과 관련성이 약한 문장은 제외 (최고 일치도의 절반 미만)
            if ov < max(1, best / 2):
                break
            if sent in seen:
                continue
            seen.add(sent)
            lines.append(f"- {sent} [{idx}]")
            if len(lines) >= 5:
                break
        return "근거 문서 요약:\n" + "\n".join(lines)


def default_llm() -> LLM:
    provider = os.environ.get("TRUSTCHAIN_LLM_PROVIDER", "auto")
    key = os.environ.get("TRUSTCHAIN_LLM_API_KEY") or os.environ.get("ANTHROPIC_API_KEY")
    if provider in ("auto", "anthropic") and key and provider != "openai":
        return AnthropicLLM(key)
    if provider == "openai" and key:
        return OpenAICompatLLM(key, os.environ.get("TRUSTCHAIN_LLM_BASE_URL", "https://api.openai.com/v1"),
                               os.environ.get("TRUSTCHAIN_LLM_MODEL", "gpt-4o-mini"))
    return ExtractiveLLM()
