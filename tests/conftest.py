from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

import pytest

from trustchain.core.config import Config
from trustchain.packages.pypi import PackageMeta

os.environ.setdefault("TRUSTCHAIN_EMBEDDER", "hashing")
os.environ.setdefault("TRUSTCHAIN_RERANKER", "lexical")
os.environ.setdefault("TRUSTCHAIN_NO_KIWI", "1")
os.environ.setdefault("TRUSTCHAIN_FEED", "0")

NOW = datetime(2026, 9, 1, tzinfo=timezone.utc)


def legit(name: str, **kw) -> PackageMeta:
    base = dict(name=name, exists=True, latest_version="2.0.0", first_release=NOW - timedelta(days=3000),
                last_release=NOW - timedelta(days=30), release_count=80, maintainer_count=3, description_len=8000,
                has_wheel=True, repository=f"github.com/org/{name}")
    base.update(kw)
    return PackageMeta(**base)


def malicious(name: str, **kw) -> PackageMeta:
    base = dict(name=name, exists=True, latest_version="0.0.1", first_release=NOW - timedelta(days=3),
                last_release=NOW - timedelta(days=3), release_count=1, maintainer_count=0, description_len=20,
                has_wheel=False, repository=None)
    base.update(kw)
    return PackageMeta(**base)


class FakePyPI:
    def __init__(self, metas: dict[str, PackageMeta]):
        self.metas = metas

    def get(self, name: str) -> PackageMeta:
        from packaging.utils import canonicalize_name

        n = canonicalize_name(name)
        return self.metas.get(n) or PackageMeta(name=n, exists=False)


@pytest.fixture
def cfg(tmp_path) -> Config:
    c = Config(root=tmp_path)
    c.offline = True
    return c


@pytest.fixture
def fake_pypi() -> FakePyPI:
    return FakePyPI({
        "requests": legit("requests"),
        "numpy": legit("numpy"),
        "fastapi": legit("fastapi"),
        "pyyaml": legit("pyyaml"),
        "reqeusts": malicious("reqeusts"),
        "numpyy": malicious("numpyy"),
        "internal-lib": malicious("internal-lib"),
        "sklearn": legit("sklearn", release_count=3),
        "tiny-new-lib": malicious("tiny-new-lib"),
    })
