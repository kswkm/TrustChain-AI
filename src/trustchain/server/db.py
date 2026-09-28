"""PostgreSQL(+pgvector) / SQLite 저장소 모델.

- 운영 : PostgreSQL + pgvector (지식베이스 벡터 인덱스)
- 테스트·로컬 : SQLite (벡터는 JSON 으로 저장하고 파이썬에서 유사도 계산)
모든 쿼리는 ORM/파라미터 바인딩만 사용한다 (문자열 결합 쿼리 금지).
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    create_engine,
)
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker
from sqlalchemy.types import TypeDecorator

EMBED_DIM = int(os.environ.get("TRUSTCHAIN_EMBED_DIM", "384"))


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class EmbeddingType(TypeDecorator):
    """PostgreSQL 에서는 pgvector, 그 외에는 JSON 배열."""

    impl = JSON
    cache_ok = True

    def load_dialect_impl(self, dialect):
        if dialect.name == "postgresql":
            try:
                from pgvector.sqlalchemy import Vector

                return dialect.type_descriptor(Vector(EMBED_DIM))
            except ImportError:
                pass
        return dialect.type_descriptor(JSON())

    def process_result_value(self, value, dialect):
        if value is None:
            return None
        return [float(x) for x in value]


class Service(Base):
    __tablename__ = "services"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    repo: Mapped[str | None] = mapped_column(String(256))
    owner_contact: Mapped[str | None] = mapped_column(String(256))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    artifacts: Mapped[list["Artifact"]] = relationship(back_populates="service", cascade="all, delete-orphan")


class Artifact(Base):
    __tablename__ = "artifacts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    service_id: Mapped[int] = mapped_column(ForeignKey("services.id"), index=True)
    image: Mapped[str | None] = mapped_column(String(512))
    digest: Mapped[str | None] = mapped_column(String(80), index=True)
    git_sha: Mapped[str | None] = mapped_column(String(64))
    signed: Mapped[bool] = mapped_column(Boolean, default=False)
    provenance: Mapped[bool] = mapped_column(Boolean, default=False)
    deployed: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    service: Mapped[Service] = relationship(back_populates="artifacts")
    components: Mapped[list["Component"]] = relationship(back_populates="artifact", cascade="all, delete-orphan")


class Component(Base):
    __tablename__ = "components"
    __table_args__ = (Index("ix_components_eco_name", "ecosystem", "name"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    artifact_id: Mapped[int] = mapped_column(ForeignKey("artifacts.id"), index=True)
    name: Mapped[str] = mapped_column(String(256))
    version: Mapped[str | None] = mapped_column(String(128))
    purl: Mapped[str | None] = mapped_column(String(512))
    ecosystem: Mapped[str | None] = mapped_column(String(32))
    type: Mapped[str] = mapped_column(String(32), default="library")
    sha256: Mapped[str | None] = mapped_column(String(64))
    artifact: Mapped[Artifact] = relationship(back_populates="components")


class ScanReport(Base):
    __tablename__ = "scan_reports"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    service_id: Mapped[int] = mapped_column(ForeignKey("services.id"), index=True)
    artifact_id: Mapped[int | None] = mapped_column(ForeignKey("artifacts.id"))
    passed: Mapped[bool] = mapped_column(Boolean)
    summary: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    findings: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)


class GateEvent(Base):
    """차단/통과 이력 (commit·build·deploy·admission 단계)."""

    __tablename__ = "gate_events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    service_id: Mapped[int] = mapped_column(ForeignKey("services.id"), index=True)
    stage: Mapped[str] = mapped_column(String(32))
    image: Mapped[str | None] = mapped_column(String(512))
    passed: Mapped[bool] = mapped_column(Boolean)
    reason: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    summary: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[str] = mapped_column(String(16), default="MEDIUM")
    cvss: Mapped[float | None] = mapped_column(Float)
    aliases: Mapped[list[str]] = mapped_column(JSON, default=list)
    modified: Mapped[str | None] = mapped_column(String(40))
    raw: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Alert(Base):
    __tablename__ = "alerts"
    __table_args__ = (UniqueConstraint("service_id", "vuln_id", "component", "version", name="uq_alert"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    service_id: Mapped[int] = mapped_column(ForeignKey("services.id"), index=True)
    vuln_id: Mapped[str] = mapped_column(String(64))
    component: Mapped[str] = mapped_column(String(256))
    version: Mapped[str | None] = mapped_column(String(128))
    severity: Mapped[str] = mapped_column(String(16))
    fixed_versions: Mapped[list[str]] = mapped_column(JSON, default=list)
    matched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    notified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    resolved: Mapped[bool] = mapped_column(Boolean, default=False)


class ApiToken(Base):
    __tablename__ = "api_tokens"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128))
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    role: Mapped[str] = mapped_column(String(16))  # admin | ingest | reader
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_used: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)


class KnowledgeChunk(Base):
    __tablename__ = "knowledge_chunks"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    doc_id: Mapped[str] = mapped_column(String(128), index=True)
    chunk_id: Mapped[str] = mapped_column(String(160), unique=True)
    source: Mapped[str] = mapped_column(String(32))  # osv | nvd | cwe | kisa
    title: Mapped[str] = mapped_column(String(512))
    section: Mapped[str] = mapped_column(String(64), default="")
    text: Mapped[str] = mapped_column(Text)
    meta: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    embedding: Mapped[list[float] | None] = mapped_column(EmbeddingType)


class FeedState(Base):
    __tablename__ = "feed_state"
    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[str] = mapped_column(String(256))


def database_url() -> str:
    return os.environ.get("TRUSTCHAIN_DATABASE_URL", "sqlite:///trustchain.db")


def make_engine(url: str | None = None) -> Engine:
    url = url or database_url()
    kw: dict[str, Any] = {"pool_pre_ping": True}
    if url.startswith("sqlite"):
        kw["connect_args"] = {"check_same_thread": False}
        if url in ("sqlite://", "sqlite:///:memory:"):
            from sqlalchemy.pool import StaticPool

            kw["poolclass"] = StaticPool
    engine = create_engine(url, **kw)
    return engine


def init_db(engine: Engine) -> None:
    if engine.dialect.name == "postgresql":
        from sqlalchemy import text

        with engine.begin() as conn:
            conn.execute(text("CREATE EXTENSION IF NOT EXISTS vector"))
    Base.metadata.create_all(engine)


def make_session_factory(engine: Engine) -> sessionmaker:
    return sessionmaker(bind=engine, expire_on_commit=False)
