"""F3 패키지 위험 분류 모델 : Keras 학습·평가 기록·설명 배치 추론 (TensorFlow 가 있을 때만 실행되는 테스트 포함)."""

import hashlib
import json
import sys
import types
from importlib import resources
from pathlib import Path

import pytest

from trustchain.packages import classifier
from trustchain.packages.checker import PackageChecker
from trustchain.packages.classifier import (
    KERAS_MODEL_FILE,
    KERAS_MODEL_SHA256,
    LABELS,
    KerasModel,
    LinearModel,
    load_default_model,
    predict,
)
from trustchain.packages.pypi import PackageMeta
from trustchain.packages.requirements import Dependency
from trustchain.packages.training import build_dataset, evaluate, split, train_and_save, train_keras


def test_keras_explain_batch_matches_single(tmp_path):
    pytest.importorskip("keras")
    train, test = split(build_dataset(seed=7), seed=7)
    train_keras(train[:300], str(tmp_path / "m.keras"), seed=7)
    m = KerasModel(tmp_path / "m.keras")
    x = test[0].x
    base = m.predict_proba(x)
    expected = []
    for i in range(len(x)):
        x2 = list(x)
        x2[i] = 0.0
        expected.append(base[2] - m.predict_proba(x2)[2])
    assert m._contributions(x, 2) == pytest.approx(expected, abs=1e-5)


def test_train_keras_is_reproducible(tmp_path):
    pytest.importorskip("keras")
    train, _ = split(build_dataset(seed=7), seed=7)
    train_keras(train[:300], str(tmp_path / "a.keras"), seed=7)
    train_keras(train[:300], str(tmp_path / "b.keras"), seed=7)
    a, b = KerasModel(tmp_path / "a.keras"), KerasModel(tmp_path / "b.keras")
    assert a.predict_proba(train[0].x) == pytest.approx(b.predict_proba(train[0].x), abs=1e-6)


def test_train_and_save_writes_eval_meta(tmp_path):
    pytest.importorskip("keras")
    rep = train_and_save(str(tmp_path / "p.keras"), backend="keras", seed=7)
    meta = json.loads((tmp_path / "p.keras.json").read_text(encoding="utf-8"))
    assert meta["eval"] == rep and meta["seed"] == 7
    assert meta["sha256"] == (tmp_path / "p.sha256").read_text().split()[0]
    assert {"trained_at", "n_train", "dataset", "tensorflow", "keras"} <= meta.keys()


def test_bundled_keras_hash_matches_constant():
    data = resources.files("trustchain.data").joinpath(KERAS_MODEL_FILE).read_bytes()
    assert hashlib.sha256(data).hexdigest() == KERAS_MODEL_SHA256


def test_auto_without_keras_uses_linear(monkeypatch):
    monkeypatch.delenv("TRUSTCHAIN_PKG_MODEL", raising=False)
    monkeypatch.setitem(sys.modules, "keras", None)  # import keras → ImportError
    assert isinstance(load_default_model(), LinearModel)


def test_keras2_falls_back_to_linear(monkeypatch):
    monkeypatch.delenv("TRUSTCHAIN_PKG_MODEL", raising=False)
    monkeypatch.setitem(sys.modules, "keras", types.SimpleNamespace(__version__="2.15.0"))
    assert isinstance(load_default_model(), LinearModel)


def test_forced_keras_without_keras_raises(monkeypatch):
    monkeypatch.setenv("TRUSTCHAIN_PKG_MODEL", "keras")
    monkeypatch.setitem(sys.modules, "keras", None)
    with pytest.raises(RuntimeError, match="tensorflow"):
        load_default_model()


def test_invalid_env_value_raises(monkeypatch):
    monkeypatch.setenv("TRUSTCHAIN_PKG_MODEL", "torch")
    with pytest.raises(ValueError):
        load_default_model()


def test_hash_mismatch_is_error_not_fallback(monkeypatch):
    monkeypatch.setenv("TRUSTCHAIN_PKG_MODEL", "keras")
    monkeypatch.setattr(classifier, "KERAS_MODEL_SHA256", "0" * 64)
    monkeypatch.setitem(sys.modules, "keras", types.SimpleNamespace(__version__="3.8.0"))
    with pytest.raises(ValueError, match="해시"):
        load_default_model()


def test_verdict_reports_model(cfg, fake_pypi):
    v = PackageChecker(cfg, fake_pypi).check_name("reqeusts")
    assert v.to_dict()["model"] == "경량 선형 모델"  # conftest 가 linear 로 고정


def test_default_model_is_keras_when_available(monkeypatch):
    pytest.importorskip("keras")
    monkeypatch.delenv("TRUSTCHAIN_PKG_MODEL", raising=False)
    m = load_default_model()
    assert m.backend == "TensorFlow(Keras)"
    assert predict(m, [0.0] * 12).label in LABELS


def test_bundled_keras_meets_target(monkeypatch):
    pytest.importorskip("keras")
    monkeypatch.setenv("TRUSTCHAIN_PKG_MODEL", "keras")
    _, test = split(build_dataset(seed=7), seed=7)
    assert evaluate(load_default_model(), test)["risk_detection_f1"] >= 0.9


def _fake_keras(load_error: Exception) -> types.SimpleNamespace:
    def load_model(*a, **kw):
        raise load_error

    return types.SimpleNamespace(__version__="3.8.0", saving=types.SimpleNamespace(load_model=load_model))


def test_auto_unloadable_keras_falls_back_to_linear(monkeypatch):
    # Keras 3.5~3.12 는 3.15 로 저장한 모델 설정을 읽지 못한다 → CLI 가 죽지 않고 경량 모델로 대체
    monkeypatch.delenv("TRUSTCHAIN_PKG_MODEL", raising=False)
    monkeypatch.setitem(sys.modules, "keras", _fake_keras(TypeError("Unrecognized keyword arguments")))
    assert isinstance(load_default_model(), LinearModel)


def test_forced_unloadable_keras_raises_runtime(monkeypatch):
    monkeypatch.setenv("TRUSTCHAIN_PKG_MODEL", "keras")
    monkeypatch.setitem(sys.modules, "keras", _fake_keras(TypeError("Unrecognized keyword arguments")))
    with pytest.raises(RuntimeError, match="keras"):
        load_default_model()


def test_auto_hash_mismatch_still_raises_integrity_error(monkeypatch):
    # 자동 모드의 대체 경로가 무결성 오류까지 삼키면 안 된다
    monkeypatch.delenv("TRUSTCHAIN_PKG_MODEL", raising=False)
    monkeypatch.setattr(classifier, "KERAS_MODEL_SHA256", "0" * 64)
    monkeypatch.setitem(sys.modules, "keras", _fake_keras(AssertionError("must not load")))
    with pytest.raises(classifier.ModelIntegrityError):
        load_default_model()


def test_ci_gate_pins_keras_version_of_bundled_model():
    # 게이트에서 모델을 읽는 Keras 버전이 학습 버전과 달라지지 않도록 CI 설치 줄에 고정
    ver = json.loads(resources.files("trustchain.data").joinpath("package_model.keras.json").read_text("utf-8"))["keras"]
    ci = (Path(__file__).resolve().parents[1] / ".github" / "workflows" / "trustchain-ci.yml").read_text(encoding="utf-8")
    assert f"keras=={ver}" in ci


@pytest.mark.parametrize(("dep", "label"), [
    (Dependency("fastapi-auth-shield", "fastapi-auth-shield"), "규칙 (PyPI 에 없는 패키지)"),
    (Dependency("internal-lib", "internal-lib"), "규칙 (허용 목록)"),
    (Dependency("private-pkg", "private-pkg", url="https://files.example.com/private_pkg-1.0-py3-none-any.whl"),
     "규칙 (직접 URL 참조)"),
    (Dependency("timeout-pkg", "timeout-pkg"), "규칙 (PyPI 조회 실패)"),
])
def test_rule_decided_verdict_names_the_rule(cfg, fake_pypi, dep, label):
    # 분류 모델이 판정하지 않은 결과에 모델 이름을 붙이지 않고, 무엇이 판정했는지 밝힌다
    cfg.allow_packages = ["internal-lib"]
    fake_pypi.metas["timeout-pkg"] = PackageMeta(name="timeout-pkg", exists=False, lookup_error="timeout")
    assert PackageChecker(cfg, fake_pypi).check_dependency(dep).to_dict()["model"] == label
