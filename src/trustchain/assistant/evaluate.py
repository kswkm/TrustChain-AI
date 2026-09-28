"""F11-6. 품질 평가 : 검색 정확도(Recall@k, MRR) 와 답변 충실도(Faithfulness).

평가셋(JSONL) 한 줄 형식
    {"question": "...", "relevant": ["kisa:security_features", "osv:PYSEC-2021-142"], "keywords": ["safe_load"]}
relevant 는 doc_id 또는 chunk_id 접두사. 검색 결과의 chunk_id/doc_id 가 접두사로 시작하면 정답으로 본다.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from trustchain.assistant.assistant import SecurityAssistant
from trustchain.assistant.retriever import Hit, HybridRetriever, LexicalReranker, Reranker
from trustchain.assistant.text import tokenize


@dataclass
class EvalItem:
    question: str
    relevant: list[str]
    keywords: list[str]


def load_eval_set(path: Path) -> list[EvalItem]:
    items = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("//"):
            d = json.loads(line)
            items.append(EvalItem(d["question"], d["relevant"], d.get("keywords", [])))
    return items


def _is_rel(h: Hit, relevant: list[str]) -> bool:
    return any(h.chunk.chunk_id.startswith(r) or h.chunk.doc_id == r for r in relevant)


def retrieval_metrics(retriever: HybridRetriever, items: list[EvalItem], k: int = 5, mode: str = "hybrid",
                      rerank: bool = False) -> dict[str, float]:
    recall_sum = mrr_sum = hit_sum = 0.0
    for it in items:
        hits = retriever.search(it.question, k=k, mode=mode, rerank=rerank)
        # 문서 단위 재현율 : 정답 문서 중 top-k 에 등장한 비율
        found = {r for r in it.relevant for h in hits if h.chunk.chunk_id.startswith(r) or h.chunk.doc_id == r}
        recall_sum += len(found) / len(it.relevant)
        hit_sum += 1.0 if found else 0.0
        for rank, h in enumerate(hits, 1):
            if _is_rel(h, it.relevant):
                mrr_sum += 1.0 / rank
                break
    n = len(items) or 1
    return {f"recall@{k}": round(recall_sum / n, 4), f"hit@{k}": round(hit_sum / n, 4), "mrr": round(mrr_sum / n, 4)}


def compare_modes(retriever: HybridRetriever, items: list[EvalItem], k: int = 5,
                  reranker: Reranker | None = None) -> dict[str, dict[str, float]]:
    """단계별 개선 효과 : BM25 → 벡터 → 하이브리드(RRF) → 하이브리드+리랭킹."""
    out = {
        "bm25": retrieval_metrics(retriever, items, k, "bm25"),
        "vector": retrieval_metrics(retriever, items, k, "vector"),
        "hybrid_rrf": retrieval_metrics(retriever, items, k, "hybrid"),
    }
    saved = retriever.reranker
    retriever.reranker = reranker or saved or LexicalReranker()
    out["hybrid_rrf+rerank"] = retrieval_metrics(retriever, items, k, "hybrid", rerank=True)
    retriever.reranker = saved
    return out


def faithfulness(answer: str, cited_texts: dict[int, str], threshold: float = 0.5) -> float:
    """인용이 달린 문장이 인용 문서로 뒷받침되는 비율 (어휘 포함률 기반 근사).

    LLM-as-judge 대신 재현 가능한 결정적 지표를 사용한다. 인용 없는 서술 문장은 뒷받침되지 않은 것으로 센다.
    """
    # "...합니다. [1]" 처럼 마침표 뒤에 붙은 인용을 문장 안으로 옮긴 뒤 분리한다
    answer = re.sub(r"([.!?。])\s*((?:\[\d{1,2}\]\s*)+)", lambda m: " " + m.group(2).strip() + m.group(1) + " ", answer)
    sents = [s.strip() for s in re.split(r"(?<=[.!?。])\s+|\n+", answer) if len(s.strip()) > 10
             and not s.strip().startswith("#") and "근거 문서 요약" not in s]
    if not sents:
        return 0.0
    ok = 0
    for s in sents:
        nums = [int(n) for n in re.findall(r"\[(\d{1,2})\]", s)]
        toks = set(tokenize(re.sub(r"\[\d+\]", "", s)))
        if not nums or not toks:
            continue
        support = set()
        for n in nums:
            support |= set(tokenize(cited_texts.get(n, "")))
        if len(toks & support) / len(toks) >= threshold:
            ok += 1
    return round(ok / len(sents), 4)


def answer_metrics(assistant: SecurityAssistant, items: list[EvalItem], k: int = 5) -> dict[str, Any]:
    faith, kw, grounded = [], [], 0
    for it in items:
        hits = assistant.retriever.search(it.question, k=k)
        ans = assistant.ask(it.question, top_k=k)
        texts = {i: h.chunk.text for i, h in enumerate(hits, 1)}
        faith.append(faithfulness(ans.answer, texts))
        grounded += int(ans.grounded)
        if it.keywords:
            kw.append(sum(1 for w in it.keywords if w.lower() in ans.answer.lower()) / len(it.keywords))
    n = len(items) or 1
    return {"faithfulness": round(sum(faith) / n, 4), "grounded_rate": round(grounded / n, 4),
            "keyword_coverage": round(sum(kw) / len(kw), 4) if kw else None}
