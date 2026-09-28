"""F4. 의존성 신뢰 점수 (0~100).

구성 (합계 100점)
- 알려진 취약점 (40) : OSV 기준, 사용 버전의 취약점 심각도에 따라 감점
- 유지관리 활동 (25) : 최근 배포 시점과 배포 이력
- 관리자 수     (10) : 단일 관리자 의존 위험
- OpenSSF Scorecard (25) : 저장소 보안 관행 점수(0~10)를 환산. 저장소를 모르면 중간값
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field

from trustchain.core.findings import Severity
from trustchain.packages.osv import Vuln
from trustchain.packages.pypi import PackageMeta

VULN_PENALTY = {Severity.CRITICAL: 40, Severity.HIGH: 25, Severity.MEDIUM: 12, Severity.LOW: 5, Severity.INFO: 0}


@dataclass
class TrustScore:
    total: int
    vulnerability: float
    maintenance: float
    maintainers: float
    scorecard: float
    notes: list[str] = field(default_factory=list)

    def grade(self) -> str:
        return "A" if self.total >= 80 else "B" if self.total >= 60 else "C" if self.total >= 40 else "D"


def compute_trust_score(meta: PackageMeta, vulns: list[Vuln], scorecard: float | None) -> TrustScore:
    notes: list[str] = []
    # 1) 취약점
    penalty = sum(VULN_PENALTY[v.severity] for v in vulns)
    vuln_pts = max(0.0, 40.0 - penalty)
    if vulns:
        worst = max(vulns, key=lambda v: v.severity.rank)
        notes.append(f"알려진 취약점 {len(vulns)}건 (최고 {worst.severity.value}: {worst.id})")
    # 2) 유지관리 : 최근 1년 내 배포면 만점, 이후 완만히 감소 / 배포 이력
    days = meta.days_since_release()
    recency = 1.0 if days is None else (1.0 if days <= 365 else math.exp(-(days - 365) / 730))
    history = min(1.0, math.log1p(meta.release_count) / math.log1p(30))
    maint_pts = 25.0 * (0.7 * recency + 0.3 * history)
    if days is not None and days > 730:
        notes.append(f"마지막 배포 후 {int(days)}일 경과 (유지관리 중단 가능성)")
    # 3) 관리자 수
    m = meta.maintainer_count
    maint_n_pts = 0.0 if m == 0 else 6.0 if m == 1 else 8.5 if m == 2 else 10.0
    if m <= 1:
        notes.append("관리자 정보가 1명 이하 (단일 관리자 의존)")
    # 4) Scorecard
    if scorecard is None:
        sc_pts = 12.5
        notes.append("OpenSSF Scorecard 결과 없음 (중간값 적용)")
    else:
        sc_pts = 2.5 * scorecard
        if scorecard < 4:
            notes.append(f"OpenSSF Scorecard {scorecard:.1f}/10 (저장소 보안 관행 미흡)")
    total = int(round(vuln_pts + maint_pts + maint_n_pts + sc_pts))
    return TrustScore(total, round(vuln_pts, 1), round(maint_pts, 1), maint_n_pts, round(sc_pts, 1), notes)
