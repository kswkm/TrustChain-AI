# F3 분류 모델 실제 PyPI 데이터 검증 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 탑재된 F3 분류 모델(Keras·경량 선형)을 실제 악성(OSV `MAL-`)·정상(PyPI) 패키지로 측정하고, 고정 스냅샷으로 재현 가능하게 문서화한다.

**Architecture:** 신규 `packages/realeval.py` 가 수집(`collect`)과 평가(`evaluate_real`)를 맡는다. 수집 결과는 `eval/pkg_real/` 에 커밋해
평가는 오프라인으로 돈다. 악성 쪽은 이름 특징 + 메타데이터 `None`(기존 중립값 경로), 정상 쪽은 실제 메타데이터로 판정한다.

**Tech Stack:** Python 3.11+, httpx, packaging, pytest; Keras 평가는 TF Docker 이미지 `trustchain-tf`

**Spec:** `docs/superpowers/specs/2026-10-01-f3-real-data-eval-design.md`

## Global Constraints

- 탑재 모델·`training.py` 는 변경하지 않는다. 재학습 없음.
- 탐지(양성) = 예측 클래스가 "주의"(1) 또는 "차단"(2). 예측 클래스는 `predict_proba` 의 argmax (`training.evaluate` 와 동일).
- 악성 쪽 메타데이터는 `None` (`classifier.meta_vector` 중립값). 정상 쪽은 스냅샷의 실제 메타데이터.
- 평가 기준 시각 `now = manifest["collected_at"]`.
- 정상 표본 : seed 7, `rank` 1,000개(hugovk 30일 순위 1,000~15,000위) + `random` 1,000개(PyPI Simple API 전체).
- 제외 : OSV 악성 이름, `popular_packages.txt`, `exists=False`, `yanked_latest`. `lookup_error` 는 제외하지 않고 `RuntimeError` 로 중단.
- 유병률 : 1% · 0.1% · 0.01%, `precision = p·TPR / (p·TPR + (1−p)·FPR)`, TPR = 악성 typosquat 탐지율, FPR = 정상 전체 오탐률.
- 스냅샷 경로 기본값 `eval/pkg_real`, 스냅샷 없음 → 종료 코드 2.
- 원천 URL :
  - OSV : `https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip`
  - 인기 순위 : `https://hugovk.github.io/top-pypi-packages/top-pypi-packages-30-days.min.json`
  - Simple API : `https://pypi.org/simple/` (헤더 `Accept: application/vnd.pypi.simple.v1+json`)
- 로컬(Windows, Python 3.13, TF 없음) 테스트 : `.venv\Scripts\python.exe -m pytest -q`. Keras 평가는 아래 TF 컨테이너.

```bash
MSYS_NO_PATHCONV=1 docker run --rm -v "$(pwd -W):/src" -w /src trustchain-tf sh -c "pip install -q -e '.[dev]' && <명령>"
```

## Review Focus

1. OSV 항목 하나에 여러 패키지가 있거나, 같은 이름이 여러 `MAL-` 항목에 나오는 경우 → 이름당 한 행, typosquat 표시는 OR. → Task 2 `test_load_osv_dedup_and_multi_affected`.
2. 정상 후보가 원천 표기와 다른 이름(`Foo_Bar`)으로 들어와 악성·인기 목록과 비교가 어긋나는 경우 → 정규화 후 비교. → Task 2 `test_sample_benign_canonicalizes_before_exclude`.
3. 후보가 부족해 목표 개수를 못 채우는 경우 → 조용히 적게 저장하지 말고 `ValueError`. → Task 2 `test_sample_benign_insufficient_raises`.
4. 스냅샷을 다른 날 다시 평가해도 나이 특징 때문에 수치가 바뀌면 안 됨 → `collected_at` 기준. → Task 3 `test_evaluate_real_uses_collected_at`.
5. Windows 에서 스냅샷을 쓰고 Linux(Docker)에서 읽을 때 인코딩·줄바꿈 차이 → UTF-8, `\n` 고정. → Task 3 `test_collect_writes_utf8_lf`.

---

### Task 1: PackageMeta 직렬화

**Files:**
- Modify: `src/trustchain/packages/pypi.py` (`PackageMeta` 에 메서드 2개)
- Test: `tests/test_realeval.py` (신규)

**Interfaces:**
- Produces: `PackageMeta.to_dict(self) -> dict[str, Any]` (datetime 은 ISO 8601 문자열), `PackageMeta.from_dict(d: dict[str, Any]) -> PackageMeta` (classmethod)

- [ ] **Step 1: 실패 테스트 작성** — `tests/test_realeval.py`

```python
from __future__ import annotations

from conftest import NOW, legit

from trustchain.packages.pypi import PackageMeta


def test_package_meta_roundtrip():
    m = legit("requests", known_vulns=["GHSA-x"])
    d = m.to_dict()
    assert d["first_release"] == m.first_release.isoformat()
    assert PackageMeta.from_dict(d) == m


def test_package_meta_roundtrip_none_dates():
    m = PackageMeta(name="x", exists=True)
    assert PackageMeta.from_dict(m.to_dict()) == m
```

- [ ] **Step 2: 실패 확인** — `.venv\Scripts\python.exe -m pytest -q tests/test_realeval.py` → FAIL (`AttributeError: 'PackageMeta' object has no attribute 'to_dict'`)

- [ ] **Step 3: 구현** — `pypi.py` 상단 import 에 `from dataclasses import asdict, dataclass, field, fields` 로 바꾸고 `PackageMeta` 에 추가:

```python
    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        for k in ("first_release", "last_release"):
            if d[k] is not None:
                d[k] = d[k].isoformat()
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> PackageMeta:
        kw = {f.name: d[f.name] for f in fields(cls) if f.name in d}
        for k in ("first_release", "last_release"):
            if kw.get(k):
                kw[k] = datetime.fromisoformat(kw[k])
        return cls(**kw)
```

- [ ] **Step 4: 통과 확인** — 같은 명령 → PASS. `.venv\Scripts\python.exe -m ruff check src tests` → 통과.

- [ ] **Step 5: Commit** — `feat(packages): PackageMeta 직렬화`

---

### Task 2: OSV 악성 목록 · 정상 표본 · 유병률 정밀도

**Files:**
- Create: `src/trustchain/packages/realeval.py`
- Test: `tests/test_realeval.py`

**Interfaces:**
- Consumes: `PackageMeta.to_dict()` (Task 1), `MetaSource` 프로토콜(`get(name) -> PackageMeta`)
- Produces:
  - `load_osv_malicious(zip_bytes: bytes) -> list[dict]` — 행 `{"name", "osv_id", "published", "typosquat": bool}`, 이름순
  - `sample_benign(candidates: dict[str, list[tuple[str, int | None]]], targets: dict[str, int], exclude: dict[str, set[str]], client: MetaSource, seed: int = 7) -> tuple[list[dict], dict[str, int]]` — 행 `{"name", "source", "rank", "meta"}`, 제외 건수 키 = `exclude` 의 키들 + `"not_found"`, `"yanked"`
  - `precision_at(tpr: float, fpr: float, prevalence: float) -> float`

- [ ] **Step 1: 실패 테스트 추가** — `tests/test_realeval.py` 에 이어서

```python
import io
import json
import zipfile

import pytest
from conftest import FakePyPI, malicious

from trustchain.packages.realeval import load_osv_malicious, precision_at, sample_benign


def osv_zip(entries: dict[str, dict]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for fn, d in entries.items():
            z.writestr(fn, json.dumps(d))
    return buf.getvalue()


def mal(id_: str, names: list[str], details: str = "") -> dict:
    return {"id": id_, "published": "2025-01-02T00:00:00Z", "summary": f"Malicious code in {names[0]} (PyPI)",
            "details": details, "affected": [{"package": {"name": n, "ecosystem": "PyPI"}} for n in names]}


def test_load_osv_only_mal_and_tag():
    z = osv_zip({
        "GHSA-aaaa.json": {"id": "GHSA-aaaa", "affected": [{"package": {"name": "django", "ecosystem": "PyPI"}}]},
        "MAL-2025-1.json": mal("MAL-2025-1", ["Reqeusts"], "Reasons:\n - typosquatting\n"),
        "MAL-2025-2.json": mal("MAL-2025-2", ["testingpy"], "infostealer"),
    })
    rows = load_osv_malicious(z)
    assert [(r["name"], r["typosquat"], r["osv_id"]) for r in rows] == [
        ("reqeusts", True, "MAL-2025-1"), ("testingpy", False, "MAL-2025-2")]


def test_load_osv_dedup_and_multi_affected():
    z = osv_zip({
        "MAL-2025-1.json": mal("MAL-2025-1", ["a-pkg", "b-pkg"]),
        "MAL-2025-2.json": mal("MAL-2025-2", ["A_Pkg"], "typosquat of apkg"),
    })
    rows = {r["name"]: r for r in load_osv_malicious(z)}
    assert sorted(rows) == ["a-pkg", "b-pkg"]
    assert rows["a-pkg"]["typosquat"] is True and rows["a-pkg"]["osv_id"] == "MAL-2025-1"


def test_precision_at():
    assert precision_at(0.5, 0.0, 0.01) == 1.0
    assert precision_at(0.0, 0.0, 0.01) == 0.0
    assert precision_at(1.0, 0.01, 0.01) == pytest.approx(0.01 / (0.01 + 0.99 * 0.01))


def _client(**metas):
    return FakePyPI({k: v for k, v in metas.items()})


def test_sample_benign_exclusions_and_refill():
    client = _client(good1=legit("good1"), good2=legit("good2"), good3=legit("good3"),
                     yank=legit("yank", yanked_latest=True))
    cands = {"rank": [("evil", 1000), ("requests", 1001), ("yank", 1002), ("ghost", 1003),
                      ("good1", 1004), ("good2", 1005), ("good3", 1006)]}
    rows, excluded = sample_benign(cands, {"rank": 3}, {"malicious": {"evil"}, "popular": {"requests"}}, client, seed=7)
    assert sorted(r["name"] for r in rows) == ["good1", "good2", "good3"]
    assert excluded == {"malicious": 1, "popular": 1, "not_found": 1, "yanked": 1}
    r = next(r for r in rows if r["name"] == "good1")
    assert r["source"] == "rank" and r["rank"] == 1004 and r["meta"]["exists"] is True


def test_sample_benign_canonicalizes_before_exclude():
    client = _client(okpkg=legit("okpkg"))
    cands = {"random": [("Evil_Pkg", None), ("OkPkg", None)]}
    rows, excluded = sample_benign(cands, {"random": 1}, {"malicious": {"evil-pkg"}}, client, seed=7)
    assert [r["name"] for r in rows] == ["okpkg"] and excluded["malicious"] == 1


def test_sample_benign_insufficient_raises():
    with pytest.raises(ValueError, match="rank"):
        sample_benign({"rank": [("good1", 1)]}, {"rank": 2}, {}, _client(good1=legit("good1")), seed=7)


def test_sample_benign_lookup_error_aborts():
    client = _client(bad=legit("bad", lookup_error="HTTP 503"))
    with pytest.raises(RuntimeError, match="bad"):
        sample_benign({"random": [("bad", None)]}, {"random": 1}, {}, client, seed=7)


def test_sample_benign_seed_reproducible():
    names = [f"p{i}" for i in range(50)]
    client = _client(**{n: legit(n) for n in names})
    cands = {"random": [(n, None) for n in names]}
    a, _ = sample_benign(cands, {"random": 10}, {}, client, seed=7)
    b, _ = sample_benign(cands, {"random": 10}, {}, client, seed=7)
    c, _ = sample_benign(cands, {"random": 10}, {}, client, seed=8)
    assert [r["name"] for r in a] == [r["name"] for r in b] != [r["name"] for r in c]
```

(`malicious` import 는 Task 3 테스트에서 쓴다. 이 단계에서 ruff 가 미사용 import 로 지적하면 Task 3 까지 `malicious` 를 빼 둔다.)

- [ ] **Step 2: 실패 확인** — `.venv\Scripts\python.exe -m pytest -q tests/test_realeval.py` → FAIL (`ModuleNotFoundError: trustchain.packages.realeval`)

- [ ] **Step 3: 구현** — `src/trustchain/packages/realeval.py`

```python
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
            if name in chosen:
                continue
            reason = next((k for k, names in exclude.items() if name in names), None)
            if reason:
                excluded[reason] += 1
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
```

- [ ] **Step 4: 통과 확인** — `.venv\Scripts\python.exe -m pytest -q tests/test_realeval.py` → PASS, `ruff check src tests` → 통과.

- [ ] **Step 5: Commit** — `feat(packages): OSV 악성 목록·정상 표본 추출·유병률 정밀도`

---

### Task 3: 수집 · 평가 · CLI

**Files:**
- Modify: `src/trustchain/packages/realeval.py` (`collect`, `evaluate_real`, `_download`)
- Modify: `src/trustchain/cli.py` (`model` 의 `action` 선택지, `--data-dir`, `cmd_model`)
- Test: `tests/test_realeval.py`

**Interfaces:**
- Consumes: Task 2 함수들, `classifier.feature_vector`, `typosquat.name_features`, `typosquat.popular_packages`, `PackageMeta.from_dict`
- Produces:
  - `collect(out_dir: Path, client: MetaSource, fetch: Callable[[str, dict[str, str]], bytes] = _download, *, now: datetime | None = None, seed: int = 7, n_rank: int = 1000, n_random: int = 1000, rank_range: tuple[int, int] = (1000, 15000)) -> dict` (manifest 반환)
  - `evaluate_real(model, snapshot_dir: Path) -> dict` (스펙 4절 출력 키). 스냅샷 없으면 `FileNotFoundError`.
  - CLI : `trustchain model real-data [--data-dir D] [--seed N]`, `trustchain model eval-real [--data-dir D] [--out MODEL]`

- [ ] **Step 1: 실패 테스트 추가**

```python
from datetime import timedelta
from pathlib import Path

from trustchain.cli import main
from trustchain.packages.classifier import LinearModel
from trustchain.packages.realeval import OSV_URL, SIMPLE_URL, TOP_URL, collect, evaluate_real


def fake_fetch(osv: bytes, top_rows: list[str], simple: list[str]):
    def fetch(url: str, headers: dict[str, str]) -> bytes:
        if url == OSV_URL:
            return osv
        if url == TOP_URL:
            return json.dumps({"last_update": "2026-10-01 00:00:00",
                               "rows": [{"project": p, "download_count": 1} for p in top_rows]}).encode()
        if url == SIMPLE_URL:
            assert headers["Accept"] == "application/vnd.pypi.simple.v1+json"
            return json.dumps({"projects": [{"name": p} for p in simple]}).encode()
        raise AssertionError(url)
    return fetch


def make_snapshot(tmp_path: Path) -> Path:
    osv = osv_zip({"MAL-2025-1.json": mal("MAL-2025-1", ["reqeusts"], "typosquatting"),
                   "MAL-2025-2.json": mal("MAL-2025-2", ["zzqxv-stealer"])})
    top = [f"top{i}" for i in range(6)]
    simple = ["tail-a", "tail-b", "reqeusts"]
    metas = {n: legit(n) for n in top + simple}
    metas["tail-b"] = malicious("tail-b")          # 실제로는 정상이지만 새로 등록된 무명 패키지 (오탐 후보)
    out = tmp_path / "snap"
    collect(out, FakePyPI(metas), fake_fetch(osv, top, simple), now=NOW, n_rank=2, n_random=2, rank_range=(3, 6))
    return out


def test_collect_writes_snapshot(tmp_path):
    out = make_snapshot(tmp_path)
    man = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
    assert man["collected_at"] == NOW.isoformat() and man["malicious"]["count"] == 2
    assert man["malicious"]["typosquat_count"] == 1 and len(man["osv"]["sha256"]) == 64
    assert man["excluded"]["malicious"] == 1                     # simple 목록의 reqeusts
    ben = [json.loads(x) for x in (out / "benign.jsonl").read_text(encoding="utf-8").splitlines()]
    assert sorted(r["source"] for r in ben) == ["random", "random", "rank", "rank"]
    assert all(3 <= r["rank"] <= 6 for r in ben if r["source"] == "rank")


def test_collect_writes_utf8_lf(tmp_path):
    out = make_snapshot(tmp_path)
    for f in ("malicious.jsonl", "benign.jsonl", "manifest.json"):
        assert b"\r\n" not in (out / f).read_bytes()


def test_evaluate_real_report(tmp_path):
    rep = evaluate_real(LinearModel.load_default(), make_snapshot(tmp_path))
    assert rep["model"] == "경량 선형 모델"
    assert rep["malicious"]["typosquat"]["n"] == 1 and rep["malicious"]["all"]["n"] == 2
    assert rep["malicious"]["typosquat"]["detection_rate"] == 1.0          # reqeusts → 주의 이상
    assert rep["benign"]["rank"]["n"] == 2 and rep["benign"]["random"]["n"] == 2 and rep["benign"]["all"]["n"] == 4
    for k in ("1%", "0.1%", "0.01%"):
        assert 0.0 <= rep["precision_at_prevalence"][k] <= 1.0
    assert rep["conditions"]["collected_at"] == NOW.isoformat()


def test_evaluate_real_uses_collected_at(tmp_path, monkeypatch):
    snap = make_snapshot(tmp_path)
    a = evaluate_real(LinearModel.load_default(), snap)
    import trustchain.packages.realeval as realeval
    monkeypatch.setattr(realeval, "_utcnow", lambda: NOW + timedelta(days=3650))
    assert evaluate_real(LinearModel.load_default(), snap) == a


def test_cli_eval_real_missing_snapshot(tmp_path, capsys):
    assert main(["model", "eval-real", "--data-dir", str(tmp_path / "none")]) == 2
    assert "real-data" in capsys.readouterr().err


def test_cli_eval_real_prints_json(tmp_path, capsys):
    snap = make_snapshot(tmp_path)
    assert main(["model", "eval-real", "--data-dir", str(snap)]) == 0
    assert json.loads(capsys.readouterr().out)["malicious"]["all"]["n"] == 2
```

- [ ] **Step 2: 실패 확인** — `.venv\Scripts\python.exe -m pytest -q tests/test_realeval.py` → FAIL (`ImportError: cannot import name 'OSV_URL'`)

- [ ] **Step 3: 구현 (`realeval.py`)** — import 추가 및 함수 추가

```python
import hashlib
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path

import httpx

from trustchain.core.http import USER_AGENT
from trustchain.packages.classifier import feature_vector
from trustchain.packages.pypi import PackageMeta
from trustchain.packages.typosquat import name_features, popular_packages

OSV_URL = "https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip"
TOP_URL = "https://hugovk.github.io/top-pypi-packages/top-pypi-packages-30-days.min.json"
SIMPLE_URL = "https://pypi.org/simple/"
SIMPLE_ACCEPT = "application/vnd.pypi.simple.v1+json"
MAX_DOWNLOAD = 200 * 1024 * 1024
PREVALENCES = {"1%": 0.01, "0.1%": 0.001, "0.01%": 0.0001}


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
    (out_dir / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=1) + "\n",
                                           encoding="utf-8", newline="\n")
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
```

- [ ] **Step 4: 구현 (`cli.py`)** — `model` 파서 수정과 `cmd_model` 분기 추가

```python
    sp = sub.add_parser("model", help="패키지 위험 분류 모델 학습·평가 (real-data/eval-real: 실제 PyPI 데이터 검증)")
    sp.add_argument("action", choices=["train", "eval", "real-data", "eval-real"])
    sp.add_argument("--backend", choices=["linear", "keras"], default="linear")
    sp.add_argument("--out", default="package_model.json")
    sp.add_argument("--seed", type=int, default=7)
    sp.add_argument("--data-dir", default="eval/pkg_real", help="실측 스냅샷 경로")
    sp.set_defaults(func=cmd_model)
```

`cmd_model` 맨 앞에 추가 (기존 `train`/`eval` 분기는 그대로):

```python
    if args.action == "real-data":
        from trustchain.core.http import CachedClient
        from trustchain.packages.pypi import PyPIClient
        from trustchain.packages.realeval import collect

        client = PyPIClient(CachedClient(Path(os.environ.get("TRUSTCHAIN_CACHE", ".trustchain-cache")), ttl=7 * 86400))
        print(json.dumps(collect(Path(args.data_dir), client, seed=args.seed), ensure_ascii=False, indent=2))
        return 0
    if args.action == "eval-real":
        from trustchain.packages.classifier import KerasModel, LinearModel
        from trustchain.packages.realeval import evaluate_real

        if not (Path(args.data_dir) / "manifest.json").is_file():
            print(f"실측 스냅샷이 없습니다: {args.data_dir}. 먼저 `trustchain model real-data` 를 실행하세요.", file=sys.stderr)
            return 2
        model = KerasModel(Path(args.out)) if args.out.endswith(".keras") else (
            LinearModel.load(Path(args.out)) if Path(args.out).is_file() else LinearModel.load_default())
        print(json.dumps(evaluate_real(model, Path(args.data_dir)), ensure_ascii=False, indent=2))
        return 0
```

- [ ] **Step 5: 통과 확인** — `.venv\Scripts\python.exe -m pytest -q` → 전부 PASS (Keras 전용 SKIP), `ruff check src tests` → 통과.
  `test_evaluate_real_report` 의 `detection_rate == 1.0` 이 실패하면 선형 모델이 `reqeusts`(메타 None)를 정상으로 본 것이다 — 단언을 고치지 말고 수치를 보고한다.

- [ ] **Step 6: Commit** — `feat(packages): 실측 데이터 수집·평가 (trustchain model real-data / eval-real)`

---

### Task 4: 실측 스냅샷 수집 · 평가 · 문서

**Files:**
- Create: `eval/pkg_real/malicious.jsonl`, `eval/pkg_real/benign.jsonl`, `eval/pkg_real/manifest.json`
- Modify: `docs/evaluation.md` (1절), `README.md` (검증 결과 각주)

**Interfaces:**
- Consumes: Task 3 CLI

- [ ] **Step 1: 수집 (네트워크, 10분 내외)** — `.venv\Scripts\trustchain.exe model real-data` → manifest JSON 출력.
  `RuntimeError`(조회 실패)면 같은 명령을 다시 실행한다 (캐시로 이어 받음). `ValueError`(후보 부족)면 멈추고 보고한다.

- [ ] **Step 2: 스냅샷 확인** — `manifest.json` 의 `malicious.count` ≥ 11,000, `typosquat_count` ≥ 500, `benign.jsonl` 2,000행,
  파일 크기 합계 5MB 이하 (`du -sh eval/pkg_real`). 넘으면 멈추고 보고한다.

- [ ] **Step 3: 평가 (두 모델)**
  - 선형 : `.venv\Scripts\trustchain.exe model eval-real > %TEMP%` 대신 스크래치 경로에 저장해 수치 확보.
  - Keras : `TF 컨테이너 "trustchain model eval-real --out src/trustchain/data/package_model.keras"` → 수치 확보.

- [ ] **Step 4: `docs/evaluation.md` 1절 갱신** — "**한계**" 문단을 다음 구성으로 교체 (수치는 Step 3 결과를 그대로):
  - 소절 제목 `### 실제 PyPI 데이터 검증` + 재현 명령 블록 (`trustchain model eval-real`, Keras 는 `--out src/trustchain/data/package_model.keras`).
  - 데이터 : OSV `MAL-` 건수·typosquatting 표기 건수, 정상 2,000개(순위 1,000~15,000위 1,000 + 전체 무작위 1,000), 수집일, 제외 건수.
  - 결과 표 (행 : 악성 typosquat 탐지율 / 악성 전체 탐지율 / 정상 순위 오탐률 / 정상 무작위 오탐률 / 정상 전체 오탐률 /
    정밀도 @1%·0.1%·0.01%, 열 : Keras · 경량 선형; 탐지율·오탐률은 "주의+차단 (차단만)" 형식).
  - 측정 조건 : 악성 쪽은 삭제되어 메타데이터가 없어 이름 특징만 쓴 보수적 수치, 전체 악성 대부분은 무작위 이름의 악성 코드라
    이름 기반 탐지 대상이 아님, 환각(존재하지 않음) 규칙은 이 평가에 포함하지 않음, 정밀도는 가정 유병률 기반.
  - 남는 한계 : 공격 당시 메타데이터를 쓴 측정은 여전히 없음.

- [ ] **Step 5: README 각주** — 분류 모델 합성 데이터 각주 다음 줄에 추가 (수치는 Step 3 Keras 결과):
  `- 실제 PyPI 데이터(OSV 악성 typosquatting N건 · 정상 2,000개) 검증 : 위장 패키지 탐지율 X, 정상 패키지 오탐률 Y (Keras, 상세 docs/evaluation.md).`

- [ ] **Step 6: 확인** — `.venv\Scripts\python.exe -m pytest -q` PASS, 문서 수치가 Step 3 출력과 일치하는지 대조.

- [ ] **Step 7: Commit** — `docs,eval: F3 분류 모델 실제 PyPI 데이터 검증 결과` (스냅샷 3개 파일 포함, 본문에 핵심 수치)
