"""업로드 파일 처리 (개발기획서 2-6 입력데이터 검증) : 형식·크기 제한, 경로 조작 방지(파일명 정규화).

업로드 파일은 서버 경로에 저장하지 않는다. 멀티파트 파서는 1MB 를 넘는 부분을 요청 처리 동안만 임시 파일로 두고 끝나면 지운다.
"""

from __future__ import annotations

import os
import re

from fastapi import HTTPException, UploadFile

ALLOWED_SUFFIXES = (".json",)
_UNSAFE = re.compile(r"[^A-Za-z0-9._-]")


def max_upload_bytes() -> int:
    return int(os.environ.get("TRUSTCHAIN_MAX_UPLOAD", str(10 * 1024 * 1024)))


def safe_filename(name: str | None) -> str:
    r"""경로 구분자(/ \)를 모두 떼어 마지막 이름만 남기고, 허용 문자 외는 '_' 로 바꾼다 (최대 128자, 확장자 유지)."""
    base = re.split(r"[\\/]", name or "")[-1].strip().lstrip(".")
    base = _UNSAFE.sub("_", base)
    if not base:
        return "upload"
    if len(base) > 128:
        stem, dot, ext = base.rpartition(".")
        base = (stem[: 127 - len(ext)] + "." + ext) if dot and len(ext) <= 16 else base[:128]
    return base


async def read_limited(file: UploadFile, limit: int | None = None) -> bytes:
    """limit 를 넘으면 413. 전체를 읽기 전에 중단한다."""
    limit = limit or max_upload_bytes()
    chunks, size = [], 0
    while True:
        chunk = await file.read(64 * 1024)
        if not chunk:
            break
        size += len(chunk)
        if size > limit:
            raise HTTPException(413, f"업로드 파일이 너무 큽니다 (최대 {limit} 바이트)")
        chunks.append(chunk)
    return b"".join(chunks)


def check_suffix(filename: str) -> None:
    if not filename.lower().endswith(ALLOWED_SUFFIXES):
        raise HTTPException(415, "CycloneDX JSON 파일(.json)만 업로드할 수 있습니다")
