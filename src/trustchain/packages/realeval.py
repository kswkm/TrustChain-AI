"""F3 분류 모델 실측 검증 : OSV 악성 패키지(MAL-) + 실제 정상 PyPI 패키지.

악성 패키지는 보고 후 PyPI 에서 삭제되어 공격 당시 메타데이터가 없으므로 이름 특징만으로 판정하고(메타데이터 중립값),
정상 패키지는 실제 메타데이터로 판정한다. 수집 결과는 eval/pkg_real/ 에 고정해 오프라인으로 재현한다.
"""

from __future__ import annotations

import io
import json
import random
import zipfile
from typing import Any

from packaging.utils import canonicalize_name

from trustchain.packages.pypi import MetaSource


def load_osv_malicious(zip_bytes: bytes) -> list[dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as z:
        for fn in sorted(z.namelist()):
            if not (fn.startswith("MAL-") and fn.endswith(".json")):
                continue
            d = json.loads(z.read(fn))
            typo = "typosquat" in f"{d.get('summary') or ''} {d.get('details') or ''}".lower()
            for a in d.get("affected") or []:
                pkg = a.get("package") or {}
                if pkg.get("ecosystem") != "PyPI" or not pkg.get("name"):
                    continue
                name = canonicalize_name(pkg["name"])
                if name in out:
                    out[name]["typosquat"] = out[name]["typosquat"] or typo
                else:
                    out[name] = {"name": name, "osv_id": d["id"], "published": d.get("published"), "typosquat": typo}
    return sorted(out.values(), key=lambda r: r["name"])


def sample_benign(candidates: dict[str, list[tuple[str, int | None]]], targets: dict[str, int],
                  exclude: dict[str, set[str]], client: MetaSource,
                  seed: int = 7) -> tuple[list[dict[str, Any]], dict[str, int]]:
    excluded = {k: 0 for k in exclude} | {"not_found": 0, "yanked": 0}
    # 목록 기반 제외(악성·인기)는 네트워크가 필요 없으므로 후보 전체에서 센다 (추출 순서와 무관한 건수)
    reason_of: dict[str, str] = {}
    for cands in candidates.values():
        for raw, _ in cands:
            name = canonicalize_name(raw)
            reason = name not in reason_of and next((k for k, names in exclude.items() if name in names), None)
            if reason:
                reason_of[name] = reason
                excluded[reason] += 1
    rows: list[dict[str, Any]] = []
    chosen: set[str] = set()
    for source, cands in candidates.items():
        want = targets[source]
        order = list(cands)
        random.Random(f"{seed}:{source}").shuffle(order)  # noqa: S311 - 재현 가능한 표본 추출 (보안 용도 아님)
        got = 0
        for raw, rank in order:
            if got == want:
                break
            name = canonicalize_name(raw)
            if name in chosen or name in reason_of:
                continue
            meta = client.get(name)
            if meta.lookup_error:
                raise RuntimeError(f"PyPI 조회 실패: {name} ({meta.lookup_error}). 다시 실행하면 캐시로 이어서 받습니다.")
            if not meta.exists:
                excluded["not_found"] += 1
                continue
            if meta.yanked_latest:
                excluded["yanked"] += 1
                continue
            chosen.add(name)
            rows.append({"name": name, "source": source, "rank": rank, "meta": meta.to_dict()})
            got += 1
        if got < want:
            raise ValueError(f"정상 후보 부족 ({source}): {got}/{want}")
    return rows, excluded


def precision_at(tpr: float, fpr: float, prevalence: float) -> float:
    tp = prevalence * tpr
    denom = tp + (1 - prevalence) * fpr
    return tp / denom if denom else 0.0
