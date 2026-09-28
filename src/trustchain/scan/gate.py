"""F5. 보안 스캔 게이트 : 코드·의존성·모델·이미지·IaC 스캔 결과를 정책으로 판정."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from trustchain.core.config import Config
from trustchain.core.findings import Finding, Report
from trustchain.core.http import CachedClient
from trustchain.iac.k8s import check_k8s, run_checkov
from trustchain.packages.checker import PackageChecker, PackageVerdict
from trustchain.packages.osv import OSVClient
from trustchain.packages.pypi import PyPIClient
from trustchain.packages.scorecard import ScorecardClient
from trustchain.scan.image import check_dockerfiles, parse_trivy, scan_image
from trustchain.scan.modelscan import scan_models
from trustchain.secure_coding.runner import run_secure_coding


@dataclass
class GateOutcome:
    report: Report
    verdicts: list[PackageVerdict] = field(default_factory=list)
    violations: list[str] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return not self.violations

    def to_dict(self) -> dict[str, Any]:
        d = self.report.to_dict()
        d["gate"] = {"passed": self.passed, "violations": self.violations}
        d["packages"] = [v.to_dict() for v in self.verdicts]
        return d


def make_checker(cfg: Config, with_scorecard: bool = True) -> PackageChecker:
    http = CachedClient(cfg.cache_dir, offline=cfg.offline)
    return PackageChecker(
        cfg, PyPIClient(http), OSVClient(http), ScorecardClient(http) if with_scorecard else None
    )


def evaluate(cfg: Config, report: Report, verdicts: list[PackageVerdict]) -> list[str]:
    counted = [f for f in report.findings if not (cfg.gate.ignore_unfixed and f.extra.get("unfixed"))]
    violations = cfg.gate.violations(Report(counted).counts())
    if cfg.gate.block_on_package_verdict:
        blocked = [v.raw_name for v in verdicts if v.verdict == "차단"]
        if blocked:
            violations.append(f"차단 판정 패키지: {', '.join(blocked)}")
        # 의존성 판정에서 나온 TC-PKG-001 은 위 blocked 에 포함되므로 import 분석 결과만 센다
        hallucinated_imports = [f for f in report.findings if f.rule_id == "TC-PKG-001" and "verdict" not in f.extra]
        if hallucinated_imports:
            violations.append(f"환각 import {len(hallucinated_imports)}건")
    return violations


def run_gate(
    cfg: Config,
    targets: list[Path] | None = None,
    image: str | None = None,
    trivy_report: Path | None = None,
    checker: PackageChecker | None = None,
    stages: set[str] | None = None,
    external_tools: bool = True,
) -> GateOutcome:
    root = cfg.root
    targets = targets or [root]
    stages = stages or {"code", "packages", "models", "docker", "iac", "image"}
    report = Report(meta={"root": str(root), "stages": sorted(stages)})
    verdicts: list[PackageVerdict] = []

    if "code" in stages:
        report.extend(run_secure_coding(targets, cfg, external=external_tools))
    if "packages" in stages:
        checker = checker or make_checker(cfg)
        verdicts, pf = checker.check_project(root)
        report.extend(pf)
    if "models" in stages:
        _, mf = scan_models(root, cfg.exclude, root)
        report.extend(mf)
    if "docker" in stages:
        report.extend(check_dockerfiles(root, cfg.exclude))
    if "iac" in stages:
        report.extend(check_k8s(root, cfg.exclude))
        if external_tools:
            report.extend(run_checkov(root))
    if "image" in stages:
        if trivy_report and trivy_report.is_file():
            report.extend(parse_trivy(json.loads(trivy_report.read_text(encoding="utf-8")), image or "image"))
        elif image:
            f, err = scan_image(image)
            report.extend(f)
            if err:
                report.meta["image_scan_error"] = err

    report.findings = [f for f in report.findings if f.rule_id not in cfg.disabled_rules]
    return GateOutcome(report, verdicts, evaluate(cfg, report, verdicts))


def findings_by_category(findings: list[Finding]) -> dict[str, int]:
    out: dict[str, int] = {}
    for f in findings:
        out[f.category] = out.get(f.category, 0) + 1
    return out
