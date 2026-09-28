"""수집 API 요청/응답 스키마 (pydantic) : 형식·길이·범위를 모두 제한한다."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

NAME = r"^[A-Za-z0-9][A-Za-z0-9._\-/]{0,127}$"
DIGEST = r"^sha256:[0-9a-f]{64}$"


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class FindingIn(_Strict):
    model_config = ConfigDict(extra="allow", str_strip_whitespace=True)
    rule_id: str = Field(max_length=128)
    title: str = Field(max_length=512)
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    message: str = Field(max_length=4000)
    category: str = Field(default="code", max_length=32)
    file: str | None = Field(default=None, max_length=1024)
    line: int | None = Field(default=None, ge=0, le=10_000_000)
    cwe: str | None = Field(default=None, max_length=32)
    kisa: str | None = Field(default=None, max_length=256)
    fix: str | None = Field(default=None, max_length=4000)
    tool: str = Field(default="trustchain", max_length=64)


class ReportIn(_Strict):
    service: str = Field(pattern=NAME)
    repo: str | None = Field(default=None, max_length=256)
    image: str | None = Field(default=None, max_length=512)
    digest: str | None = Field(default=None, pattern=DIGEST)
    git_sha: str | None = Field(default=None, pattern=r"^[0-9a-f]{7,64}$")
    passed: bool
    summary: dict[str, int] = Field(default_factory=dict)
    violations: list[str] = Field(default_factory=list, max_length=100)
    findings: list[FindingIn] = Field(default_factory=list, max_length=5000)
    signed: bool = False
    provenance: bool = False


class SBOMIn(_Strict):
    service: str = Field(pattern=NAME)
    image: str | None = Field(default=None, max_length=512)
    digest: str | None = Field(default=None, pattern=DIGEST)
    git_sha: str | None = Field(default=None, pattern=r"^[0-9a-f]{7,64}$")
    sbom: dict[str, Any]

    @field_validator("sbom")
    @classmethod
    def _cyclonedx(cls, v: dict[str, Any]) -> dict[str, Any]:
        if v.get("bomFormat") != "CycloneDX" or not isinstance(v.get("components", []), list):
            raise ValueError("CycloneDX JSON SBOM 이 아닙니다")
        if len(v.get("components", [])) > 50_000:
            raise ValueError("구성요소가 너무 많습니다")
        return v


class EventIn(_Strict):
    service: str = Field(pattern=NAME)
    stage: Literal["commit", "build", "deploy", "admission"]
    image: str | None = Field(default=None, max_length=512)
    passed: bool
    reason: str = Field(default="", max_length=4000)


class AskIn(_Strict):
    question: str = Field(min_length=2, max_length=2000)
    service: str | None = Field(default=None, pattern=NAME)
    top_k: int = Field(default=5, ge=1, le=20)


class Citation(BaseModel):
    n: int
    chunk_id: str
    title: str
    source: str
    url: str | None = None


class AskOut(BaseModel):
    answer: str
    citations: list[Citation]
    grounded: bool
    priorities: list[dict[str, Any]] = Field(default_factory=list)


class ServiceOut(BaseModel):
    name: str
    repo: str | None
    trust_score: int
    latest_digest: str | None
    components: int
    open_alerts: int
    last_gate_passed: bool | None
