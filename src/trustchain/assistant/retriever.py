"""F11-3·4. 하이브리드 검색(BM25 + 벡터, RRF 결합) 과 Cross-encoder 리랭킹."""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Protocol, Sequence

from trustchain.assistant.ingest import Chunk
from trustchain.assistant.text import BM25, Embedder, HashingEmbedder, cosine, tokenize

RRF_K = 60


@dataclass
class Hit:
    chunk: Chunk
    score: float
    bm25_rank: int | None = None
    vec_rank: int | None = None


def rrf(rankings: Sequence[Sequence[int]], k: int = RRF_K) -> dict[int, float]:
    """Reciprocal Rank Fusion : score(d) = Σ 1 / (k + rank)."""
    out: dict[int, float] = {}
    for ranking in rankings:
        for r, idx in enumerate(ranking, 1):
            out[idx] = out.get(idx, 0.0) + 1.0 / (k + r)
    return out


class Reranker(Protocol):
    def rerank(self, query: str, hits: list[Hit], top_k: int) -> list[Hit]: ...


class LexicalReranker:
    """Cross-encoder 가 없을 때의 대체 : 질의 용어 포함률 + 식별자(CVE/패키지) 정확 일치 가중치."""

    def rerank(self, query: str, hits: list[Hit], top_k: int) -> list[Hit]:
        q = set(tokenize(query))
        ids = {t for t in q if t.startswith(("cve-", "ghsa-", "pysec-", "cwe-")) or "-" in t}
        scored = []
        for h in hits:
            d = set(tokenize(h.chunk.title + " " + h.chunk.text))
            overlap = len(q & d) / (len(q) or 1)
            idb = 1.0 if ids and ids & d else 0.0
            sec = 0.1 if any(w in query for w in ("조치", "해결", "고치", "수정", "업그레이드", "방법")) and \
                h.chunk.section in ("조치 방법", "완화 방법") else 0.0
            scored.append((overlap + idb + sec + h.score * 5, h))
        scored.sort(key=lambda t: -t[0])
        return [Hit(h.chunk, s, h.bm25_rank, h.vec_rank) for s, h in scored[:top_k]]


class CrossEncoderReranker:
    def __init__(self, model_name: str | None = None):
        from sentence_transformers import CrossEncoder

        self.model = CrossEncoder(model_name or os.environ.get(
            "TRUSTCHAIN_RERANK_MODEL", "cross-encoder/mmarco-mMiniLMv2-L12-H384-v1"), max_length=512)

    def rerank(self, query: str, hits: list[Hit], top_k: int) -> list[Hit]:
        if not hits:
            return []
        scores = self.model.predict([(query, h.chunk.text) for h in hits])
        order = sorted(zip(scores, hits), key=lambda t: -float(t[0]))
        return [Hit(h.chunk, float(s), h.bm25_rank, h.vec_rank) for s, h in order[:top_k]]


def default_reranker() -> Reranker:
    if os.environ.get("TRUSTCHAIN_RERANKER", "auto") != "lexical":
        try:
            return CrossEncoderReranker()
        except Exception as e:  # 모델 미설치/다운로드 불가 → 대체 구현
            logging.getLogger("trustchain.assistant").info("대체 구현 사용: %s", e.__class__.__name__)
    return LexicalReranker()


class HybridRetriever:
    """메모리 인덱스. DB 저장 시에도 검색 시점에는 이 인덱스를 구성해 사용한다 (pgvector 는 선택적 가속)."""

    def __init__(self, chunks: list[Chunk], embedder: Embedder | None = None,
                 vectors: list[list[float]] | None = None, reranker: Reranker | None = None):
        self.chunks = chunks
        self.embedder = embedder or HashingEmbedder()
        self.bm25 = BM25([tokenize(c.title + " " + c.text) for c in chunks])
        self.vectors = vectors if vectors is not None else self.embedder.embed([c.text for c in chunks])
        self.reranker = reranker

    def bm25_ranking(self, query: str, n: int) -> list[int]:
        s = self.bm25.scores(tokenize(query))
        return [i for i in sorted(range(len(s)), key=lambda i: -s[i])[:n] if s[i] > 0]

    def vector_ranking(self, query: str, n: int) -> list[int]:
        qv = self.embedder.embed([query], is_query=True)[0]
        s = [cosine(qv, v) for v in self.vectors]
        return sorted(range(len(s)), key=lambda i: -s[i])[:n]

    def search(self, query: str, k: int = 5, mode: str = "hybrid", rerank: bool = True,
               candidates: int = 30) -> list[Hit]:
        b = self.bm25_ranking(query, candidates) if mode in ("hybrid", "bm25") else []
        v = self.vector_ranking(query, candidates) if mode in ("hybrid", "vector") else []
        fused = rrf([r for r in (b, v) if r])
        b_rank = {idx: r for r, idx in enumerate(b, 1)}
        v_rank = {idx: r for r, idx in enumerate(v, 1)}
        hits = [Hit(self.chunks[i], s, b_rank.get(i), v_rank.get(i))
                for i, s in sorted(fused.items(), key=lambda t: -t[1])[:candidates]]
        if rerank and self.reranker is not None:
            return self.reranker.rerank(query, hits, k)
        return hits[:k]
