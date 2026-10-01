"""F3 분류 모델 실측 검증 : OSV 악성 패키지(MAL-) + 실제 정상 PyPI 패키지.

악성 패키지는 보고 후 PyPI 에서 삭제되어 공격 당시 메타데이터가 없으므로 이름 특징만으로 판정하고(메타데이터 중립값),
정상 패키지는 실제 메타데이터로 판정한다. 수집 결과는 eval/pkg_real/ 에 고정해 오프라인으로 재현한다.
"""

from __future__ import annotations

import bisect
import hashlib
import io
import json
import random
import zipfile
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
from packaging.utils import canonicalize_name

from trustchain.core.http import USER_AGENT
from trustchain.packages.classifier import feature_vector
from trustchain.packages.pypi import MetaSource, PackageMeta
from trustchain.packages.typosquat import name_features, popular_packages

OSV_URL = "https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip"
TOP_URL = "https://hugovk.github.io/top-pypi-packages/top-pypi-packages-30-days.min.json"
SIMPLE_URL = "https://pypi.org/simple/"
SIMPLE_ACCEPT = "application/vnd.pypi.simple.v1+json"
MAX_DOWNLOAD = 200 * 1024 * 1024


def load_osv_malicious(zip_bytes: bytes) -> list[dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as z:
        for fn in sorted(z.namelist()):
            if not (fn.startswith("MAL-") and fn.endswith(".json")):
                continue
            d = json.loads(z.read(fn))
            if d.get("withdrawn"):  # 오탐으로 철회된 보고는 악성 라벨이 아니다
                continue
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


def auc(pos: list[float], neg: list[float]) -> float:
    """악성 점수가 정상 점수보다 높을 확률 (동점은 0.5, Mann-Whitney U / (n·m))."""
    if not pos or not neg:
        return 0.0
    ns = sorted(neg)
    wins = 0.0
    for x in pos:
        lo, hi = bisect.bisect_left(ns, x), bisect.bisect_right(ns, x)
        wins += lo + 0.5 * (hi - lo)
    return wins / (len(pos) * len(ns))


def tpr_at_fpr(pos: list[float], neg: list[float], target: float) -> tuple[float, float]:
    """정상 오탐률이 target 이하인 가장 낮은 기준점(점수 >= 기준이면 위험)에서의 (탐지율, 달성 오탐률).

    기준점은 정상 점수 값에서만 고르므로 동점 묶음은 통째로 기준 위 또는 아래에 놓인다.
    """
    if not pos or not neg:
        return 0.0, 0.0
    top = max(neg)
    best = (sum(1 for x in pos if x > top) / len(pos), 0.0)  # 모든 정상 점수보다 위
    for t in sorted(set(neg), reverse=True):
        fpr = sum(1 for x in neg if x >= t) / len(neg)
        if fpr > target:
            break
        best = (sum(1 for x in pos if x >= t) / len(pos), fpr)
    return best


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _download(url: str, headers: dict[str, str]) -> bytes:
    with httpx.Client(timeout=httpx.Timeout(120.0, connect=10.0), follow_redirects=True,
                      headers={"User-Agent": USER_AGENT, **headers}) as c, c.stream("GET", url) as r:
        r.raise_for_status()
        chunks, size = [], 0
        for b in r.iter_bytes():
            size += len(b)
            if size > MAX_DOWNLOAD:
                raise ValueError(f"다운로드가 너무 큽니다: {url}")
            chunks.append(b)
    return b"".join(chunks)


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8", newline="\n") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n")


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines() if x.strip()]


def collect(out_dir: Path, client: MetaSource, fetch: Callable[[str, dict[str, str]], bytes] = _download, *,
            now: datetime | None = None, seed: int = 7, n_rank: int = 1000, n_random: int = 1000,
            rank_range: tuple[int, int] = (1000, 15000)) -> dict[str, Any]:
    now = now or _utcnow()
    osv = fetch(OSV_URL, {})
    mal = load_osv_malicious(osv)
    top_raw = fetch(TOP_URL, {})
    top = json.loads(top_raw)
    simple = json.loads(fetch(SIMPLE_URL, {"Accept": SIMPLE_ACCEPT}))
    lo, hi = rank_range
    cands = {
        "rank": [(r["project"], i) for i, r in enumerate(top["rows"], start=1) if lo <= i <= hi],
        "random": [(p["name"], None) for p in simple["projects"]],
    }
    exclude = {"malicious": {r["name"] for r in mal}, "popular": set(popular_packages())}
    benign, excluded = sample_benign(cands, {"rank": n_rank, "random": n_random}, exclude, client, seed)
    out_dir.mkdir(parents=True, exist_ok=True)
    _write_jsonl(out_dir / "malicious.jsonl", mal)
    _write_jsonl(out_dir / "benign.jsonl", benign)
    manifest = {
        "collected_at": now.isoformat(), "seed": seed,
        "osv": {"url": OSV_URL, "sha256": hashlib.sha256(osv).hexdigest()},
        "malicious": {"count": len(mal), "typosquat_count": sum(r["typosquat"] for r in mal)},
        "top": {"url": TOP_URL, "last_update": top.get("last_update"), "sha256": hashlib.sha256(top_raw).hexdigest(),
                "rank_range": [lo, hi]},
        "simple": {"url": SIMPLE_URL, "projects": len(simple["projects"])},
        "benign": {"rank": n_rank, "random": n_random}, "excluded": excluded,
    }
    with (out_dir / "manifest.json").open("w", encoding="utf-8", newline="\n") as f:
        f.write(json.dumps(manifest, ensure_ascii=False, indent=1) + "\n")
    return manifest


def _fp_rates(classes: list[int]) -> dict[str, Any]:
    n = len(classes)
    hit = sum(1 for c in classes if c > 0) / n if n else 0.0
    block = sum(1 for c in classes if c == 2) / n if n else 0.0
    return {"n": n, "false_positive_rate": round(hit, 4), "block_fp_rate": round(block, 4)}


def _name_signal(pos: list[float], neg: list[float]) -> dict[str, Any]:
    t1, f1 = tpr_at_fpr(pos, neg, 0.01)
    t5, f5 = tpr_at_fpr(pos, neg, 0.05)
    return {"n_pos": len(pos), "n_neg": len(neg), "auc": round(auc(pos, neg), 4),
            "tpr_at_fpr_1pct": round(t1, 4), "fpr_1pct": round(f1, 4),
            "tpr_at_fpr_5pct": round(t5, 4), "fpr_5pct": round(f5, 4)}


def evaluate_real(model: Any, snapshot_dir: Path) -> dict[str, Any]:
    man_path = snapshot_dir / "manifest.json"
    if not man_path.is_file():
        raise FileNotFoundError(man_path)
    manifest = json.loads(man_path.read_text(encoding="utf-8"))
    now = datetime.fromisoformat(manifest["collected_at"])
    pop = popular_packages()

    def proba(name: str, meta: PackageMeta | None) -> list[float]:
        return model.predict_proba(feature_vector(name_features(name, popular=pop), meta, now))

    def cls(pr: list[float]) -> int:
        return max(range(len(pr)), key=lambda i: pr[i])

    mal = _read_jsonl(snapshot_dir / "malicious.jsonl")
    ben = _read_jsonl(snapshot_dir / "benign.jsonl")
    # 이름 신호 : 악성·정상 모두 메타데이터 없이 (같은 조건) 위험 확률 = 1 - P(정상)
    mal_s = [(r, 1.0 - proba(r["name"], None)[0]) for r in mal]
    ben_s = [1.0 - proba(r["name"], None)[0] for r in ben]
    # 실사용 오탐 : 정상 패키지를 실제 메타데이터로 판정
    ben_c = [(r, cls(proba(r["name"], PackageMeta.from_dict(r["meta"])))) for r in ben]
    return {
        "model": getattr(model, "backend", ""),
        "name_signal": {"typosquat": _name_signal([s for r, s in mal_s if r["typosquat"]], ben_s),
                        "all": _name_signal([s for _, s in mal_s], ben_s)},
        "benign": {s: _fp_rates([c for r, c in ben_c if r["source"] == s]) for s in ("rank", "random")}
        | {"all": _fp_rates([c for _, c in ben_c])},
        "conditions": {"name_signal": "악성·정상 모두 메타데이터 없이 위험 확률(1-P(정상)) 비교 (악성은 삭제되어 메타데이터 없음)",
                       "benign_metadata": "수집 시점 PyPI 실제 메타데이터",
                       "collected_at": manifest["collected_at"], "osv_sha256": manifest["osv"]["sha256"]},
    }
