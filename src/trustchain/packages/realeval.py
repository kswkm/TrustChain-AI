"""F3 분류 모델 실측 검증 : OSV 악성 패키지(MAL-) + 실제 정상 PyPI 패키지.

악성 패키지는 보고 후 PyPI 에서 삭제되어 공격 당시 메타데이터가 없으므로 이름 특징만으로 판정하고(메타데이터 중립값),
정상 패키지는 실제 메타데이터로 판정한다. 수집 결과는 eval/pkg_real/ 에 고정해 오프라인으로 재현한다.
"""

from __future__ import annotations

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
PREVALENCES = {"1%": 0.01, "0.1%": 0.001, "0.01%": 0.0001}


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


def _rates(classes: list[int], positive: str) -> dict[str, Any]:
    n = len(classes)
    hit = sum(1 for c in classes if c > 0) / n if n else 0.0
    block = sum(1 for c in classes if c == 2) / n if n else 0.0
    if positive == "malicious":
        return {"n": n, "detection_rate": round(hit, 4), "block_rate": round(block, 4)}
    return {"n": n, "false_positive_rate": round(hit, 4), "block_fp_rate": round(block, 4)}


def evaluate_real(model: Any, snapshot_dir: Path) -> dict[str, Any]:
    man_path = snapshot_dir / "manifest.json"
    if not man_path.is_file():
        raise FileNotFoundError(man_path)
    manifest = json.loads(man_path.read_text(encoding="utf-8"))
    now = datetime.fromisoformat(manifest["collected_at"])
    pop = popular_packages()

    def cls(name: str, meta: PackageMeta | None) -> int:
        pr = model.predict_proba(feature_vector(name_features(name, popular=pop), meta, now))
        return max(range(len(pr)), key=lambda i: pr[i])

    mal = _read_jsonl(snapshot_dir / "malicious.jsonl")
    ben = _read_jsonl(snapshot_dir / "benign.jsonl")
    mal_c = [(r, cls(r["name"], None)) for r in mal]
    ben_c = [(r, cls(r["name"], PackageMeta.from_dict(r["meta"]))) for r in ben]
    m_typo = _rates([c for r, c in mal_c if r["typosquat"]], "malicious")
    b_all = _rates([c for _, c in ben_c], "benign")
    return {
        "model": getattr(model, "backend", ""),
        "malicious": {"typosquat": m_typo, "all": _rates([c for _, c in mal_c], "malicious")},
        "benign": {s: _rates([c for r, c in ben_c if r["source"] == s], "benign") for s in ("rank", "random")}
        | {"all": b_all},
        "precision_at_prevalence": {k: round(precision_at(m_typo["detection_rate"], b_all["false_positive_rate"], p), 4)
                                    for k, p in PREVALENCES.items()},
        "conditions": {"malicious_metadata": "미사용 (삭제된 패키지, 이름 특징만)",
                       "benign_metadata": "수집 시점 PyPI 실제 메타데이터",
                       "collected_at": manifest["collected_at"], "osv_sha256": manifest["osv"]["sha256"]},
    }
