"""설정 로드 : trustchain.toml 또는 pyproject.toml 의 [tool.trustchain].

설정 한 번으로 전 주기 점검을 적용하는 것이 목표이므로, 파일이 없어도
안전한 기본값으로 동작한다.
"""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from trustchain.core.findings import Severity


@dataclass
class GatePolicy:
    # 심각도별 허용 최대 건수. 초과 시 게이트 실패. (예: CRITICAL 1건 이상이면 중단)
    max_critical: int = 0
    max_high: int = 10**6
    max_medium: int = 10**6
    # 패키지 판정이 '차단'이면 무조건 실패
    block_on_package_verdict: bool = True
    # 신뢰 점수 하한 (0 이면 비활성)
    min_trust_score: int = 0
    # 이미지 스캔에서 배포판이 패치를 내지 않은(FixedVersion 없음) 취약점은 보고만 하고 게이트 판정에서 제외
    ignore_unfixed: bool = True
    # 심각도 한도를 적용할 발견 분류 (code·package·dependency·model·image·iac). 비우면 전부
    categories: list[str] = field(default_factory=list)

    def violations(self, counts: dict[str, int]) -> list[str]:
        out = []
        for sev, limit in (("CRITICAL", self.max_critical), ("HIGH", self.max_high), ("MEDIUM", self.max_medium)):
            if counts.get(sev, 0) > limit:
                out.append(f"{sev} {counts[sev]}건 (허용 {limit}건)")
        return out


@dataclass
class ProvenancePolicy:
    # Verify Gate 가 요구하는 빌드 출처
    source_repo: str = ""  # 예: github.com/org/repo
    branch: str = "main"
    workflow_path: str = ""  # 예: .github/workflows/trustchain-ci.yml
    # 서명한 재사용 워크플로우가 있는 저장소 (Fulcio 인증서 SAN). 비우면 source_repo 와 같다고 본다
    signer_repo: str = ""
    oidc_issuer: str = "https://token.actions.githubusercontent.com"
    builder_id: str = (
        "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml"
    )


@dataclass
class Config:
    root: Path = field(default_factory=Path.cwd)
    exclude: list[str] = field(
        default_factory=lambda: [".git", ".venv", "venv", "node_modules", "__pycache__", "build", "dist", ".tox"]
    )
    offline: bool = False
    gate: GatePolicy = field(default_factory=GatePolicy)
    # 커밋 시점(trustchain check · pre-commit/pre-push) 기준 : 취약 코드(HIGH 이상)를 개발 단계에서 차단한다.
    # trustchain.toml 의 [check] 로 완화할 수 있다. 빌드 게이트([gate])와 별개
    # 커밋 시점은 작성 중인 코드(code)와 패키지 판정(package)만 센다. 의존성 권고문은 빌드 게이트가 판정
    check: GatePolicy = field(default_factory=lambda: GatePolicy(max_high=0, categories=["code", "package"]))
    provenance: ProvenancePolicy = field(default_factory=ProvenancePolicy)
    disabled_rules: list[str] = field(default_factory=list)
    allow_packages: list[str] = field(default_factory=list)  # 사내 패키지 등 판정 예외
    model_dirs: list[str] = field(default_factory=lambda: ["models", "model"])
    min_severity: Severity = Severity.LOW
    cache_dir: Path = field(default_factory=lambda: Path(os.environ.get("TRUSTCHAIN_CACHE", ".trustchain-cache")))


def _apply(obj: Any, data: dict[str, Any]) -> None:
    for k, v in data.items():
        if not hasattr(obj, k):
            continue
        cur = getattr(obj, k)
        if isinstance(v, dict) and hasattr(cur, "__dataclass_fields__"):
            _apply(cur, v)
        elif isinstance(cur, Severity):
            setattr(obj, k, Severity.parse(v))
        elif isinstance(cur, Path):
            setattr(obj, k, Path(v))
        else:
            setattr(obj, k, v)


def load_config(root: str | Path = ".") -> Config:
    root = Path(root).resolve()
    cfg = Config(root=root)
    data: dict[str, Any] = {}
    tc = root / "trustchain.toml"
    pp = root / "pyproject.toml"
    if tc.is_file():
        data = tomllib.loads(tc.read_text(encoding="utf-8"))
    elif pp.is_file():
        data = tomllib.loads(pp.read_text(encoding="utf-8")).get("tool", {}).get("trustchain", {})
    _apply(cfg, data)
    if os.environ.get("TRUSTCHAIN_OFFLINE") == "1":
        cfg.offline = True
    return cfg
