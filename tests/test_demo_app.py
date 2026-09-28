"""시연 서비스가 AI-BOM 해시가 다른(변조된) 모델의 로드를 거부하는지 확인 (TensorFlow 없이)."""

import importlib.util
import zipfile
from pathlib import Path

import pytest

from trustchain.bom.aibom import generate_aibom
from trustchain.bom.sbom import write_bom

ROOT = Path(__file__).resolve().parents[1]


def load_demo(monkeypatch, model: Path, aibom: Path):
    monkeypatch.setenv("MODEL_PATH", str(model))
    monkeypatch.setenv("AIBOM_PATH", str(aibom))
    spec = importlib.util.spec_from_file_location("demo_main", ROOT / "demo" / "mnist-api" / "app" / "main.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_demo_rejects_tampered_model(tmp_path, monkeypatch):
    (tmp_path / "model").mkdir()
    model = tmp_path / "model" / "mnist.keras"
    with zipfile.ZipFile(model, "w") as z:
        z.writestr("config.json", "{}")
    (tmp_path / "models.toml").write_text('[[model]]\nname="mnist-cnn"\nversion="1"\npath="model/mnist.keras"\n',
                                          encoding="utf-8")
    write_bom(generate_aibom(tmp_path, ["model"], [], "demo"), tmp_path / "aibom.cdx.json")
    mod = load_demo(monkeypatch, model, tmp_path / "aibom.cdx.json")
    assert len(mod.expected_hash()) == 64
    with zipfile.ZipFile(model, "w") as z:  # 공격자가 모델 교체
        z.writestr("config.json", '{"evil": 1}')
    with pytest.raises(RuntimeError, match="해시"):
        mod.load_verified_model()


def test_demo_input_validation(tmp_path, monkeypatch):
    mod = load_demo(monkeypatch, tmp_path / "m.keras", tmp_path / "a.json")
    with pytest.raises(ValueError):
        mod.PredictIn(pixels=[0.5] * 10)
    with pytest.raises(ValueError):
        mod.PredictIn(pixels=[2.0] * 784)
    assert len(mod.PredictIn(pixels=[0.0] * 784).pixels) == 784
