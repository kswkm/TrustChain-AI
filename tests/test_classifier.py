"""F3 패키지 위험 분류 모델 : Keras 학습·평가 기록·설명 배치 추론 (TensorFlow 가 있을 때만 실행되는 테스트 포함)."""

import json

import pytest

from trustchain.packages.classifier import KerasModel
from trustchain.packages.training import build_dataset, split, train_and_save, train_keras


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
