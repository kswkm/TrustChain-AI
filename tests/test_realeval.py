from __future__ import annotations

import io
import json
import zipfile

import pytest
from conftest import FakePyPI, legit

from trustchain.packages.pypi import PackageMeta
from trustchain.packages.realeval import load_osv_malicious, precision_at, sample_benign


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
