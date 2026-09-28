"""지식베이스 저장소 : 청크·임베딩을 DB(knowledge_chunks)에 저장하고 검색 인덱스를 구성한다.

PostgreSQL 에서는 pgvector 코사인 거리(<=>) 로 벡터 검색을 DB 에서 수행한다.
"""

from __future__ import annotations

from typing import Iterable

from sqlalchemy import select, text
from sqlalchemy.orm import Session, sessionmaker

from trustchain.assistant.ingest import Chunk, builtin_knowledge
from trustchain.assistant.retriever import HybridRetriever, Reranker
from trustchain.assistant.text import Embedder
from trustchain.server.db import KnowledgeChunk


def upsert_chunks(s: Session, chunks: Iterable[Chunk], embedder: Embedder, batch: int = 64) -> int:
    chunks = list(chunks)
    n = 0
    for i in range(0, len(chunks), batch):
        part = chunks[i : i + batch]
        vecs = embedder.embed([c.text for c in part])
        for c, v in zip(part, vecs):
            row = s.scalar(select(KnowledgeChunk).where(KnowledgeChunk.chunk_id == c.chunk_id))
            if row is None:
                row = KnowledgeChunk(chunk_id=c.chunk_id)
                s.add(row)
            row.doc_id, row.source, row.title, row.section = c.doc_id, c.source, c.title[:512], c.section[:64]
            row.text, row.meta, row.embedding = c.text, c.meta, v
            n += 1
        s.commit()
    return n


def load_chunks(s: Session) -> tuple[list[Chunk], list[list[float]]]:
    rows = s.scalars(select(KnowledgeChunk).order_by(KnowledgeChunk.id)).all()
    chunks = [Chunk(r.chunk_id, r.doc_id, r.source, r.title, r.section, r.text, r.meta or {}) for r in rows]
    return chunks, [list(r.embedding or []) for r in rows]


def build_retriever(sf: sessionmaker, embedder: Embedder, reranker: Reranker | None = None) -> HybridRetriever:
    """DB 에 저장된 지식베이스로 검색기 생성. 비어 있으면 내장 지식을 먼저 적재한다."""
    with sf() as s:
        chunks, vecs = load_chunks(s)
        if not chunks:
            upsert_chunks(s, builtin_knowledge(), embedder)
            chunks, vecs = load_chunks(s)
        dialect = s.get_bind().dialect.name
    dims_ok = all(len(v) == embedder.dim for v in vecs)
    retr = HybridRetriever(chunks, embedder, vecs if dims_ok and vecs else None, reranker)
    if dialect == "postgresql":
        index = {c.chunk_id: i for i, c in enumerate(chunks)}

        def pg_vector_ranking(query: str, n: int) -> list[int]:
            qv = embedder.embed([query], is_query=True)[0]
            vec = "[" + ",".join(f"{x:.6f}" for x in qv) + "]"
            with sf() as s2:
                # pgvector 코사인 거리 연산자 (질의 벡터는 바인딩 파라미터로 전달)
                stmt = (select(KnowledgeChunk.chunk_id)
                        .order_by(text("embedding <=> CAST(:qv AS vector)")).limit(n))
                ids = s2.scalars(stmt, {"qv": vec}).all()
            return [index[i] for i in ids if i in index]

        retr.vector_ranking = pg_vector_ranking  # type: ignore[method-assign]
    return retr
