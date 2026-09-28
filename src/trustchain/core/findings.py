"""모든 점검 모듈이 공유하는 결과(Finding) 모델과 리포트 직렬화."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Iterable


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def rank(self) -> int:
        return _RANK[self]

    @classmethod
    def parse(cls, value: str | None, default: "Severity" = None) -> "Severity":  # type: ignore[assignment]
        if value is None:
            return default or cls.MEDIUM
        v = str(value).strip().upper()
        aliases = {"ERROR": "HIGH", "WARNING": "MEDIUM", "MODERATE": "MEDIUM", "UNKNOWN": "LOW", "NOTE": "LOW"}
        v = aliases.get(v, v)
        try:
            return cls(v)
        except ValueError:
            return default or cls.MEDIUM


_RANK = {Severity.CRITICAL: 4, Severity.HIGH: 3, Severity.MEDIUM: 2, Severity.LOW: 1, Severity.INFO: 0}


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: Severity
    message: str
    category: str = "code"  # code | dependency | package | model | image | iac | provenance
    file: str | None = None
    line: int | None = None
    cwe: str | None = None
    kisa: str | None = None  # KISA 시큐어코딩 가이드 항목명
    fix: str | None = None  # 수정 예시 / 조치 방법
    tool: str = "trustchain"
    extra: dict[str, Any] = field(default_factory=dict)

    def key(self) -> tuple:
        # 같은 CVE 라도 패키지가 다르면 별개 발견 (이미지·의존성 스캔)
        return (self.rule_id, self.file, self.line, self.extra.get("pkg") or self.extra.get("package"))

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


@dataclass
class Report:
    findings: list[Finding] = field(default_factory=list)
    meta: dict[str, Any] = field(default_factory=dict)

    def extend(self, items: Iterable[Finding]) -> None:
        seen = {f.key() for f in self.findings}
        for f in items:
            if f.key() not in seen:
                self.findings.append(f)
                seen.add(f.key())

    def counts(self) -> dict[str, int]:
        out = {s.value: 0 for s in Severity}
        for f in self.findings:
            out[f.severity.value] += 1
        return out

    def sorted(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: (-f.severity.rank, f.file or "", f.line or 0))

    def to_dict(self) -> dict[str, Any]:
        return {"meta": self.meta, "summary": self.counts(), "findings": [f.to_dict() for f in self.sorted()]}

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=2)

    def to_sarif(self) -> dict[str, Any]:
        """GitHub Code Scanning 업로드용 SARIF 2.1.0."""
        level = {
            Severity.CRITICAL: "error",
            Severity.HIGH: "error",
            Severity.MEDIUM: "warning",
            Severity.LOW: "note",
            Severity.INFO: "note",
        }
        rules: dict[str, dict[str, Any]] = {}
        results = []
        for f in self.sorted():
            rules.setdefault(
                f.rule_id,
                {
                    "id": f.rule_id,
                    "name": f.title,
                    "shortDescription": {"text": f.title},
                    "help": {"text": f.fix or f.message},
                    "properties": {"tags": [t for t in (f.cwe, f.category) if t]},
                },
            )
            res: dict[str, Any] = {"ruleId": f.rule_id, "level": level[f.severity], "message": {"text": f.message}}
            if f.file:
                loc: dict[str, Any] = {"artifactLocation": {"uri": f.file.replace("\\", "/")}}
                if f.line:
                    loc["region"] = {"startLine": f.line}
                res["locations"] = [{"physicalLocation": loc}]
            results.append(res)
        return {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "TrustChain AI", "rules": list(rules.values())}},
                    "results": results,
                }
            ],
        }
