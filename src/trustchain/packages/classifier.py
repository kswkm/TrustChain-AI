"""F2·F3 패키지 위험 분류 모델 : '정상 / 주의 / 차단' 3단계 판정과 판정 근거.

- 기본 백엔드 : 학습된 다항 로지스틱 회귀 가중치(JSON)를 순수 파이썬으로 추론.
  (CLI 가 numpy·TensorFlow 없이도 동작하도록)
- Keras 백엔드 : `trustchain model train --backend keras` 로 학습한 .keras 모델.
  pickle 을 쓰지 않는 .keras 형식을 safe_mode 로 로드하며, 로드 전에 SHA-256 을 검증한다.
"""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass, field
from datetime import datetime
from importlib import resources
from pathlib import Path

from trustchain.packages.pypi import PackageMeta
from trustchain.packages.typosquat import NameFeatures

LABELS = ["정상", "주의", "차단"]
FEATURE_NAMES = [
    "name_similarity", "inv_edit_distance", "keyboard_substitution", "homoglyph", "squat_pattern", "is_popular",
    "young_package", "few_releases", "no_maintainer", "short_description", "no_wheel", "no_repository",
]
FEATURE_KO = {
    "name_similarity": "인기 패키지와 이름이 매우 유사",
    "inv_edit_distance": "인기 패키지와 편집거리가 작음",
    "keyboard_substitution": "키보드 인접 문자 치환 패턴",
    "homoglyph": "형태가 비슷한 문자(0/o, l/1/I 등) 치환",
    "squat_pattern": "구분자·접사·문자 중복/누락 위장 패턴",
    "is_popular": "인기 패키지 목록에 포함",
    "young_package": "최근에 처음 등록된 패키지",
    "few_releases": "배포 이력이 매우 적음",
    "no_maintainer": "작성자·관리자 정보 없음",
    "short_description": "설명이 거의 없음",
    "no_wheel": "휠 없이 소스 배포만 제공 (설치 시 setup.py 실행)",
    "no_repository": "소스 저장소 링크 없음",
}


def meta_vector(meta: PackageMeta | None, now: datetime | None = None) -> list[float]:
    if meta is None or not meta.exists or meta.lookup_error:
        # 메타데이터를 모르면 중립값
        return [0.5, 0.5, 0.0, 0.5, 0.0, 0.5]
    age = meta.age_days(now)
    return [
        1.0 if age is None else math.exp(-max(age, 0) / 90.0),
        math.exp(-max(meta.release_count - 1, 0) / 5.0),
        1.0 if meta.maintainer_count == 0 else 0.0,
        math.exp(-meta.description_len / 300.0),
        0.0 if meta.has_wheel else 1.0,
        0.0 if meta.repository else 1.0,
    ]


def feature_vector(nf: NameFeatures, meta: PackageMeta | None, now: datetime | None = None) -> list[float]:
    return nf.vector() + meta_vector(meta, now)


@dataclass
class Prediction:
    label: str
    probs: dict[str, float]
    reasons: list[str] = field(default_factory=list)


class LinearModel:
    """softmax(W·x + b). 가중치는 JSON 으로 저장 (역직렬화 시 코드 실행 없음)."""

    def __init__(self, weights: list[list[float]], bias: list[float], meta: dict | None = None):
        self.W = weights  # [n_classes][n_features]
        self.b = bias
        self.meta = meta or {}

    @classmethod
    def load_default(cls) -> "LinearModel":
        data = json.loads(resources.files("trustchain.data").joinpath("package_model.json").read_text("utf-8"))
        return cls(data["weights"], data["bias"], data.get("meta"))

    @classmethod
    def load(cls, path: Path) -> "LinearModel":
        data = json.loads(Path(path).read_text("utf-8"))
        return cls(data["weights"], data["bias"], data.get("meta"))

    def save(self, path: Path) -> None:
        Path(path).write_text(
            json.dumps({"features": FEATURE_NAMES, "labels": LABELS, "weights": self.W, "bias": self.b,
                        "meta": self.meta}, ensure_ascii=False, indent=1),
            encoding="utf-8",
        )

    def logits(self, x: list[float]) -> list[float]:
        return [sum(w * v for w, v in zip(row, x)) + b for row, b in zip(self.W, self.b)]

    def predict_proba(self, x: list[float]) -> list[float]:
        z = self.logits(x)
        m = max(z)
        e = [math.exp(v - m) for v in z]
        s = sum(e)
        return [v / s for v in e]

    def explain(self, x: list[float], cls_idx: int, top: int = 3) -> list[str]:
        # 판정 클래스 로짓에 대한 특징별 기여도 (정상 클래스 대비)
        contrib = [
            (FEATURE_NAMES[i], (self.W[cls_idx][i] - self.W[0][i]) * x[i]) for i in range(len(x))
        ] if cls_idx != 0 else [(FEATURE_NAMES[i], (self.W[0][i] - self.W[2][i]) * x[i]) for i in range(len(x))]
        contrib.sort(key=lambda t: -t[1])
        return [FEATURE_KO[n] for n, c in contrib[:top] if c > 0.05]


class KerasModel:
    def __init__(self, path: Path, expected_sha256: str | None = None):
        path = Path(path)
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        sidecar = path.with_suffix(".sha256")
        expected = expected_sha256 or (sidecar.read_text().strip().split()[0] if sidecar.exists() else None)
        if not expected or digest != expected:
            raise ValueError(f"모델 해시 불일치 또는 해시 정보 없음: {path.name}")
        import keras  # 선택 의존성

        self.model = keras.saving.load_model(path, safe_mode=True, compile=False)

    def predict_proba(self, x: list[float]) -> list[float]:
        import numpy as np

        return [float(v) for v in self.model.predict(np.array([x], dtype="float32"), verbose=0)[0]]

    def explain(self, x: list[float], cls_idx: int, top: int = 3) -> list[str]:
        base = self.predict_proba(x)[cls_idx]
        scores = []
        for i in range(len(x)):
            x2 = list(x)
            x2[i] = 0.0
            scores.append((FEATURE_NAMES[i], base - self.predict_proba(x2)[cls_idx]))
        scores.sort(key=lambda t: -t[1])
        return [FEATURE_KO[n] for n, c in scores[:top] if c > 0.02]


def predict(model: LinearModel | KerasModel, x: list[float]) -> Prediction:
    p = model.predict_proba(x)
    idx = max(range(len(p)), key=lambda i: p[i])
    return Prediction(LABELS[idx], {LABELS[i]: round(p[i], 4) for i in range(len(p))}, model.explain(x, idx))
