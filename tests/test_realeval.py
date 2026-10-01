from __future__ import annotations

from conftest import legit

from trustchain.packages.pypi import PackageMeta


def test_package_meta_roundtrip():
    m = legit("requests", known_vulns=["GHSA-x"])
    d = m.to_dict()
    assert d["first_release"] == m.first_release.isoformat()
    assert PackageMeta.from_dict(d) == m


def test_package_meta_roundtrip_none_dates():
    m = PackageMeta(name="x", exists=True)
    assert PackageMeta.from_dict(m.to_dict()) == m
