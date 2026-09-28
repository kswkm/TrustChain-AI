"""API 토큰 인증 : 토큰 원문은 저장하지 않고 SHA-256 해시만 저장한다.

토큰은 secrets.token_urlsafe(32) (256bit 엔트로피) 로 생성하므로, 느린 해시 없이
SHA-256 만으로도 무차별 대입이 불가능하다. 역할은 admin > ingest > reader.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets

from sqlalchemy import select
from sqlalchemy.orm import Session

from trustchain.server.db import ApiToken, utcnow

ROLES = {"reader": 1, "ingest": 2, "admin": 3}
PREFIX = "tc_"


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_token(session: Session, name: str, role: str) -> str:
    if role not in ROLES:
        raise ValueError(f"알 수 없는 역할: {role}")
    token = PREFIX + secrets.token_urlsafe(32)
    session.add(ApiToken(name=name[:128], token_hash=hash_token(token), role=role))
    session.commit()
    return token


def authenticate(session: Session, token: str | None) -> ApiToken | None:
    if not token or not token.startswith(PREFIX) or len(token) > 200:
        return None
    h = hash_token(token)
    row = session.scalar(select(ApiToken).where(ApiToken.token_hash == h))
    if row is None or row.revoked or not hmac.compare_digest(row.token_hash, h):
        return None
    row.last_used = utcnow()
    session.commit()
    return row


def has_role(tok: ApiToken, required: str) -> bool:
    return ROLES.get(tok.role, 0) >= ROLES[required]
