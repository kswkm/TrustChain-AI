"""F2 환각 패키지 탐지 · F3 타이포스쿼팅 탐지 · F4 신뢰 점수 통합 판정기."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from packaging.utils import canonicalize_name

from trustchain.core.config import Config
from trustchain.core.findings import Finding, Severity
from trustchain.packages.classifier import KerasModel, LinearModel, Prediction, feature_vector, load_default_model, predict
from trustchain.packages.imports import IMPORT_MAP, candidate_distributions, collect_imports
from trustchain.packages.osv import OSVClient, Vuln
from trustchain.packages.pypi import MetaSource, PackageMeta
from trustchain.packages.requirements import Dependency, discover_dependencies
from trustchain.packages.scorecard import ScorecardClient
from trustchain.packages.trust_score import TrustScore, compute_trust_score
from trustchain.packages.typosquat import name_features, popular_packages

# 코드에서 import 하지 않아도 정상인 개발·빌드 도구
TOOL_PACKAGES = {
    "pytest", "pytest-cov", "pytest-mock", "pytest-asyncio", "pytest-xdist", "coverage", "black", "isort", "ruff",
    "flake8", "mypy", "pylint", "pre-commit", "tox", "nox", "bandit", "semgrep", "pip-audit", "twine", "build",
    "wheel", "setuptools", "pip", "uvicorn", "gunicorn", "psycopg", "psycopg2", "psycopg2-binary", "python-multipart",
    "email-validator", "ipykernel", "jupyter", "notebook", "mkdocs", "sphinx", "pgvector",
}
# import 이름과 배포 이름이 달라 혼동을 노린 선점 등록이 잦은 이름
_IMPORT_ONLY_NAMES = {canonicalize_name(k): v for k, v in IMPORT_MAP.items() if canonicalize_name(k) not in
                      {canonicalize_name(d) for d in v}}
_PINNED_VCS = re.compile(r"@[0-9a-f]{40}\b")


@dataclass
class PackageVerdict:
    name: str
    raw_name: str
    version: str | None
    verdict: str  # 정상 / 주의 / 차단
    reasons: list[str] = field(default_factory=list)
    probs: dict[str, float] = field(default_factory=dict)
    nearest_popular: str | None = None
    trust: TrustScore | None = None
    vulns: list[Vuln] = field(default_factory=list)
    source: str = ""
    line: int | None = None
    model: str = ""  # 판정에 쓴 분류 모델

    def to_dict(self) -> dict:
        return {
            "name": self.name, "raw_name": self.raw_name, "version": self.version, "verdict": self.verdict,
            "reasons": self.reasons, "probs": self.probs, "nearest_popular": self.nearest_popular,
            "trust_score": self.trust.total if self.trust else None,
            "trust_grade": self.trust.grade() if self.trust else None,
            "trust_notes": self.trust.notes if self.trust else [],
            "vulns": [{"id": v.id, "severity": v.severity.value, "fixed": v.fixed_versions, "summary": v.summary}
                      for v in self.vulns],
            "source": self.source, "line": self.line, "model": self.model,
        }


_ORDER = {"정상": 0, "주의": 1, "차단": 2}


def _raise(cur: str, new: str) -> str:
    return new if _ORDER[new] > _ORDER[cur] else cur


class PackageChecker:
    def __init__(
        self,
        cfg: Config,
        pypi: MetaSource,
        osv: OSVClient | None = None,
        scorecard: ScorecardClient | None = None,
        model: LinearModel | KerasModel | None = None,
        now: datetime | None = None,
    ):
        self.cfg = cfg
        self.pypi = pypi
        self.osv = osv
        self.scorecard = scorecard
        self.model = model or load_default_model()
        self.now = now
        self.allow = {canonicalize_name(a) for a in cfg.allow_packages}

    # ---- 단일 패키지 ----
    def check_name(self, name: str, raw_name: str | None = None, version: str | None = None) -> PackageVerdict:
        dep = Dependency(canonicalize_name(name), raw_name or name, pinned_version=version)
        return self.check_dependency(dep)

    def check_dependency(self, dep: Dependency) -> PackageVerdict:
        v = PackageVerdict(dep.name, dep.raw_name, dep.pinned_version, "정상", source=dep.source, line=dep.line)
        if dep.name in self.allow:
            v.reasons.append("허용 목록(allow_packages)에 등록된 패키지")
            return v
        if dep.url:
            if dep.url.startswith("git+") and not _PINNED_VCS.search(dep.url):
                v.verdict = "주의"
                v.reasons.append("VCS 직접 참조가 커밋 해시로 고정되지 않음 (내용이 바뀌어도 탐지 불가)")
            elif not dep.url.startswith("git+"):
                v.verdict = "주의"
                v.reasons.append("레지스트리 밖 URL 직접 참조 (출처 검증 불가)")
            return v

        meta = self.pypi.get(dep.name)
        if meta.lookup_error:
            v.verdict = "주의"
            v.reasons.append(f"PyPI 조회 실패로 검증하지 못함 ({meta.lookup_error})")
            return v
        if not meta.exists:
            v.verdict = "차단"
            v.reasons.append(
                "PyPI 에 존재하지 않는 패키지입니다. AI 코딩 도구의 환각 제안일 수 있으며, "
                "공격자가 이 이름을 선점 등록하면 악성 코드가 설치됩니다."
            )
            nf = name_features(dep.name, dep.raw_name)
            if nf.nearest:
                v.nearest_popular = nf.nearest
                v.reasons.append(f"의도한 패키지가 '{nf.nearest}' 인지 확인하세요.")
            return v

        if dep.name in _IMPORT_ONLY_NAMES:
            real = ", ".join(_IMPORT_ONLY_NAMES[dep.name])
            v.verdict = "주의"
            v.reasons.append(f"'{dep.raw_name}' 는 import 이름입니다. 실제 배포 패키지는 '{real}' 입니다.")

        nf = name_features(dep.name, dep.raw_name)
        v.nearest_popular = nf.nearest
        pred: Prediction = predict(self.model, feature_vector(nf, meta, self.now))
        v.probs = pred.probs
        v.model = pred.model
        if not nf.is_popular:
            v.verdict = _raise(v.verdict, pred.label)
            if pred.label != "정상":
                parts = []
                if nf.nearest:
                    parts.append(f"유사 인기 패키지 '{nf.nearest}', 편집거리 {nf.distance}")
                if nf.pattern:
                    parts.append(nf.pattern)
                v.reasons.append(f"분류 모델 판정 '{pred.label}'" + (f" ({', '.join(parts)})" if parts else ""))
                v.reasons.extend(pred.reasons)
        age = meta.age_days(self.now)
        if age is not None and age < 7:
            v.verdict = _raise(v.verdict, "주의")
            v.reasons.append(f"최초 등록 후 {age:.0f}일밖에 지나지 않은 패키지")
            if nf.nearest and nf.distance <= 2 and not nf.is_popular:
                v.verdict = "차단"
                v.reasons.append("최근 등록 + 인기 패키지와 유사한 이름 → 타이포스쿼팅 가능성 높음")
        if nf.raw_mixed_case_confusable:
            v.verdict = "차단"
            v.reasons.append(f"대문자 'I' 로 소문자 'l' 을 위장한 이름 ('{dep.raw_name}' → '{nf.nearest}')")
        if meta.yanked_latest:
            v.verdict = _raise(v.verdict, "주의")
            v.reasons.append("최신 버전이 철회(yanked)됨")

        # F4 : 취약점 + 신뢰 점수
        if self.osv is not None:
            v.vulns = self.osv.query(dep.name, dep.pinned_version) if dep.pinned_version else []
        sc = self.scorecard.score(meta.repository) if self.scorecard else None
        v.trust = compute_trust_score(meta, v.vulns, sc)
        if self.cfg.gate.min_trust_score and v.trust.total < self.cfg.gate.min_trust_score:
            v.verdict = _raise(v.verdict, "주의")
            v.reasons.append(f"신뢰 점수 {v.trust.total}점 < 기준 {self.cfg.gate.min_trust_score}점")
        return v

    # ---- 프로젝트 ----
    def check_project(self, root: Path) -> tuple[list[PackageVerdict], list[Finding]]:
        deps = discover_dependencies(root)
        verdicts: dict[str, PackageVerdict] = {}
        for d in deps:
            if d.name not in verdicts:
                verdicts[d.name] = self.check_dependency(d)
        findings = [f for v in verdicts.values() for f in verdict_findings(v)]
        findings += self.import_mismatch(root, deps)
        return list(verdicts.values()), findings

    def import_mismatch(self, root: Path, deps: list[Dependency]) -> list[Finding]:
        """코드의 import 와 선언된 의존성 비교 (F2 : 코드와 이름이 맞지 않는 패키지)."""
        if not deps:
            return []
        declared = {d.name for d in deps}
        uses = collect_imports(root, self.cfg.exclude)
        out: list[Finding] = []
        satisfied: set[str] = set()
        for mod, use in sorted(uses.items()):
            cands = candidate_distributions(mod)
            hit = [c for c in cands if c in declared]
            if hit:
                satisfied.update(hit)
                continue
            f, line = use.files[0]
            meta: PackageMeta = self.pypi.get(cands[0])
            if meta.exists or meta.lookup_error:
                out.append(Finding(
                    rule_id="TC-PKG-003", title="선언되지 않은 import", severity=Severity.LOW, category="package",
                    file=f, line=line,
                    message=f"코드가 '{mod}' 를 import 하지만 의존성 파일에 대응 패키지({cands[0]})가 없습니다.",
                    fix=f"requirements.txt 에 올바른 배포 이름과 버전을 고정해 추가하세요 (예: {cands[0]}==<버전>).",
                ))
            else:
                out.append(Finding(
                    rule_id="TC-PKG-001", title="환각 import", severity=Severity.HIGH, category="package",
                    file=f, line=line,
                    message=f"코드가 import 하는 '{mod}' 에 해당하는 패키지가 PyPI 에 없습니다 (AI 환각 코드 가능성).",
                    fix="모듈 이름과 실제 배포 패키지를 공식 문서에서 확인하세요. 임의로 pip install 하지 마세요.",
                ))
        for d in deps:
            if d.name in satisfied or d.name in TOOL_PACKAGES or d.url:
                continue
            # 배포 이름으로 import 가능한 경우
            modname = d.name.replace("-", "_")
            if modname in uses or any(d.name in candidate_distributions(m) for m in uses):
                continue
            out.append(Finding(
                rule_id="TC-PKG-004", title="코드에서 사용하지 않는 의존성", severity=Severity.INFO, category="package",
                file=d.source, line=d.line,
                message=f"'{d.raw_name}' 는 선언되어 있지만 코드에서 import 되지 않습니다. 불필요한 공격면입니다.",
                fix="사용하지 않는 의존성은 제거하세요.",
            ))
        return out


def verdict_findings(v: PackageVerdict) -> list[Finding]:
    out: list[Finding] = []
    if v.verdict == "차단":
        hallucinated = any("존재하지 않는" in r for r in v.reasons)
        out.append(Finding(
            rule_id="TC-PKG-001" if hallucinated else "TC-PKG-002",
            title="환각 패키지" if hallucinated else "타이포스쿼팅 의심 패키지",
            severity=Severity.CRITICAL if hallucinated else Severity.HIGH,
            category="package", file=v.source, line=v.line,
            message=f"'{v.raw_name}' 차단: " + " / ".join(v.reasons),
            fix=(f"'{v.nearest_popular}' 가 의도한 패키지라면 이름을 수정하세요." if v.nearest_popular else
                 "패키지 이름과 출처를 공식 문서에서 확인하세요."),
            cwe="CWE-1357", extra={"verdict": v.to_dict()},
        ))
    elif v.verdict == "주의":
        out.append(Finding(
            rule_id="TC-PKG-005", title="검토가 필요한 패키지", severity=Severity.MEDIUM, category="package",
            file=v.source, line=v.line, message=f"'{v.raw_name}' 주의: " + " / ".join(v.reasons),
            fix="패키지 저장소·관리자·배포 이력을 확인한 뒤 allow_packages 에 등록하거나 대체 패키지를 사용하세요.",
            extra={"verdict": v.to_dict()},
        ))
    for vu in v.vulns:
        fixed = f" → {vu.fixed_versions[0]} 이상으로 업그레이드" if vu.fixed_versions else ""
        out.append(Finding(
            rule_id=vu.id, title=f"취약한 의존성 {v.name}=={v.version}", severity=vu.severity, category="dependency",
            file=v.source, line=v.line, message=f"{vu.id} {('(' + vu.cve + ')') if vu.cve and vu.cve != vu.id else ''} "
            f"{vu.summary}".strip(), fix=f"{v.name}{fixed}" if fixed else "패치 버전이 없습니다. 대체 패키지나 완화 조치를 검토하세요.",
            tool="osv", extra={"package": v.name, "version": v.version, "fixed": vu.fixed_versions, "cvss": vu.cvss_score},
        ))
    return out


def is_popular(name: str) -> bool:
    return canonicalize_name(name) in popular_packages()
