from __future__ import annotations

import io
import json
import zipfile
from datetime import timedelta
from pathlib import Path

import pytest
from conftest import NOW, FakePyPI, legit, malicious

from trustchain.cli import main
from trustchain.packages.classifier import LinearModel
from trustchain.packages.pypi import PackageMeta
from trustchain.packages.realeval import (
    OSV_URL,
    SIMPLE_URL,
    TOP_URL,
    collect,
    evaluate_real,
    load_osv_malicious,
    precision_at,
    sample_benign,
)


def test_package_meta_roundtrip():
    m = legit("requests", known_vulns=["GHSA-x"])
    d = m.to_dict()
    assert d["first_release"] == m.first_release.isoformat()
    assert PackageMeta.from_dict(d) == m


def test_package_meta_roundtrip_none_dates():
    m = PackageMeta(name="x", exists=True)
    assert PackageMeta.from_dict(m.to_dict()) == m


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
    return FakePyPI(dict(metas))


def test_sample_benign_exclusions_and_refill():
    client = _client(good1=legit("good1"), good2=legit("good2"), good3=legit("good3"),
                     yank=legit("yank", yanked_latest=True))
    cands = {"rank": [("evil", 1000), ("requests", 1001), ("yank", 1002), ("ghost", 1003),
                      ("good1", 1004), ("good2", 1005), ("good3", 1006)]}
    rows, excluded = sample_benign(cands, {"rank": 3}, {"malicious": {"evil"}, "popular": {"requests"}}, client, seed=7)
    assert sorted(r["name"] for r in rows) == ["good1", "good2", "good3"]
    # 목록 기반 제외는 후보 전체에서 세므로 정확, 조회 기반 제외는 추출 순서에 따라 0 또는 1
    assert excluded["malicious"] == 1 and excluded["popular"] == 1
    assert excluded["not_found"] in (0, 1) and excluded["yanked"] in (0, 1)
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
    for grp in (rep["malicious"]["typosquat"], rep["malicious"]["all"]):
        assert 0.0 <= grp["detection_rate"] <= 1.0 and grp["block_rate"] <= grp["detection_rate"]
    assert rep["benign"]["rank"]["n"] == 2 and rep["benign"]["random"]["n"] == 2 and rep["benign"]["all"]["n"] == 4
    for k in ("1%", "0.1%", "0.01%"):
        assert 0.0 <= rep["precision_at_prevalence"][k] <= 1.0
    assert rep["conditions"]["collected_at"] == NOW.isoformat()


def test_evaluate_real_uses_collected_at(tmp_path, monkeypatch):
    import trustchain.packages.realeval as realeval

    snap = make_snapshot(tmp_path)
    seen = []
    real_fv = realeval.feature_vector
    monkeypatch.setattr(realeval, "feature_vector", lambda nf, meta, now: seen.append(now) or real_fv(nf, meta, now))
    monkeypatch.setattr(realeval, "_utcnow", lambda: NOW + timedelta(days=3650))
    evaluate_real(LinearModel.load_default(), snap)
    assert seen and set(seen) == {NOW}


def test_cli_eval_real_missing_snapshot(tmp_path, capsys):
    assert main(["model", "eval-real", "--data-dir", str(tmp_path / "none")]) == 2
    assert "real-data" in capsys.readouterr().err


def test_cli_eval_real_prints_json(tmp_path, capsys):
    snap = make_snapshot(tmp_path)
    assert main(["model", "eval-real", "--data-dir", str(snap)]) == 0
    assert json.loads(capsys.readouterr().out)["malicious"]["all"]["n"] == 2
