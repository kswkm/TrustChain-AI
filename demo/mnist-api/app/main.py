"""시연용 서비스 : MNIST 손글씨 숫자 추론 API (TensorFlow · FastAPI).

모델 로드 전 AI-BOM 에 기록된 가중치 SHA-256 과 실제 파일을 대조하고, pickle 을 쓰지 않는
Keras v3(.keras) 형식을 safe_mode=True 로 로드한다. 해시가 다르면 서비스가 시작되지 않는다.
"""

import hashlib
import json
import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path

import numpy as np
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, ConfigDict, Field, field_validator

BASE = Path(__file__).resolve().parents[1]
MODEL_PATH = Path(os.environ.get("MODEL_PATH", BASE / "model" / "mnist.keras"))
AIBOM_PATH = Path(os.environ.get("AIBOM_PATH", BASE / "aibom.cdx.json"))
log = logging.getLogger("mnist-api")
state: dict = {}


def expected_hash() -> str:
    """AI-BOM 에서 모델 가중치 해시를 찾는다."""
    bom = json.loads(AIBOM_PATH.read_text(encoding="utf-8"))
    rel = MODEL_PATH.relative_to(BASE).as_posix() if MODEL_PATH.is_relative_to(BASE) else None
    for c in bom.get("components", []):
        props = {p["name"]: p["value"] for p in c.get("properties", [])}
        path = props.get("trustchain:path", "")
        if c.get("type") == "machine-learning-model" and (path == rel or rel is None and
                                                          Path(path).name == MODEL_PATH.name):
            return next(h["content"] for h in c["hashes"] if h["alg"] == "SHA-256")
    raise RuntimeError("AI-BOM 에 모델 정보가 없습니다")


def load_verified_model():
    digest = hashlib.sha256(MODEL_PATH.read_bytes()).hexdigest()
    if digest != expected_hash():
        raise RuntimeError("모델 가중치 해시가 AI-BOM 과 다릅니다 - 변조된 모델일 수 있어 로드를 거부합니다")
    import keras

    return keras.saving.load_model(MODEL_PATH, safe_mode=True, compile=False)


@asynccontextmanager
async def lifespan(app: FastAPI):
    state["model"] = load_verified_model()
    log.info("모델 로드 완료 (AI-BOM 해시 검증 통과)")
    yield


app = FastAPI(title="MNIST Inference API", lifespan=lifespan, docs_url=None, redoc_url=None)


class PredictIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    # 28x28 흑백 이미지, 0~1 로 정규화된 784 개 값
    pixels: list[float] = Field(min_length=784, max_length=784)

    @field_validator("pixels")
    @classmethod
    def _range(cls, v: list[float]) -> list[float]:
        if any(not (0.0 <= x <= 1.0) for x in v):
            raise ValueError("픽셀 값은 0~1 범위여야 합니다")
        return v


class PredictOut(BaseModel):
    digit: int
    confidence: float
    probabilities: list[float]


@app.get("/healthz")
def healthz() -> dict:
    return {"status": "ok", "model_loaded": "model" in state}


@app.post("/predict", response_model=PredictOut)
def predict(body: PredictIn) -> PredictOut:
    model = state.get("model")
    if model is None:
        raise HTTPException(503, "모델이 준비되지 않았습니다")
    x = np.asarray(body.pixels, dtype="float32").reshape(1, 28, 28, 1)
    probs = model.predict(x, verbose=0)[0]
    d = int(np.argmax(probs))
    return PredictOut(digit=d, confidence=float(probs[d]), probabilities=[round(float(p), 5) for p in probs])
