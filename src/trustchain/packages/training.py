"""패키지 위험 분류 모델 학습·평가 데이터셋 생성.

평가셋은 '자체 구축' 데이터다 : 인기 패키지 이름에 공개 보고된 공격 유형
(키보드 인접 치환, 형태 유사 문자, 구분자·접사 변형, 문자 누락/중복/자리바꿈)을
적용해 위장 이름을 만들고, 메타데이터는 정상/악성 패키지의 전형적인 분포에서
표본 추출한다. 학습/평가는 '원본 인기 패키지' 단위로 분리해 이름 누수를 막는다.

이 합성 데이터의 성능은 실제 PyPI 분포의 성능을 보장하지 않으므로,
`scripts/collect_labeled_packages.py` 로 실측 라벨 데이터를 추가해 재평가한다.
"""

from __future__ import annotations

import random
import string
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from trustchain.packages.classifier import FEATURE_NAMES, LABELS, LinearModel, feature_vector
from trustchain.packages.pypi import PackageMeta
from trustchain.packages.typosquat import ADJ, name_features, osa_distance, popular_packages

NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _mutate(name: str, rng: random.Random) -> str:
    kind = rng.choice(["keyboard", "homoglyph", "omit", "dup", "swap", "affix", "sep"])
    letters = [i for i, c in enumerate(name) if c.isalpha()]
    if not letters:
        return name + "s"
    i = rng.choice(letters)
    if kind == "keyboard" and ADJ.get(name[i]):
        return name[:i] + rng.choice(sorted(ADJ[name[i]])) + name[i + 1 :]
    if kind == "homoglyph":
        for a, b in [("o", "0"), ("l", "1"), ("i", "l"), ("l", "i"), ("m", "rn"), ("w", "vv")]:
            if a in name:
                j = name.index(a)
                return name[:j] + b + name[j + 1 :]
    if kind == "omit" and len(name) > 4:
        return name[:i] + name[i + 1 :]
    if kind == "dup":
        return name[: i + 1] + name[i] + name[i + 1 :]
    if kind == "swap" and i + 1 < len(name) and name[i] != name[i + 1]:
        return name[:i] + name[i + 1] + name[i] + name[i + 2 :]
    if kind == "affix":
        return rng.choice(["python-", "py", "python3-"]) + name if rng.random() < 0.5 else name + rng.choice(
            ["-python", "3", "-py", "s", "-dev"]
        )
    if kind == "sep" and "-" in name:
        return name.replace("-", rng.choice(["", "_", "."]), 1)
    return name[:i] + rng.choice(string.ascii_lowercase) + name[i + 1 :]


def _random_name(rng: random.Random) -> str:
    syll = ["ka", "zu", "mo", "ri", "tex", "vel", "no", "qua", "lin", "por", "sek", "dra", "fi", "gon", "hub",
            "yan", "wix", "tor", "bel", "cro", "mek", "sol", "tri", "vox"]
    s = "".join(rng.choice(syll) for _ in range(rng.randint(2, 3)))
    if rng.random() < 0.3:
        s += "-" + rng.choice(["utils", "client", "kit", "io", "tools", "sdk"])
    return s


def _meta(rng: random.Random, name: str, profile: str) -> PackageMeta:
    if profile == "legit":
        age = rng.uniform(200, 5000)
        rel = rng.randint(5, 300)
        maint = rng.randint(1, 6)
        desc = int(rng.lognormvariate(8, 1))
        wheel = rng.random() < 0.9
        repo = rng.random() < 0.92
    elif profile == "legit_small":
        age = rng.uniform(60, 3000)
        rel = rng.randint(1, 40)
        maint = rng.randint(0, 2) if rng.random() < 0.3 else 1
        desc = int(rng.lognormvariate(6.5, 1.2))
        wheel = rng.random() < 0.7
        repo = rng.random() < 0.75
    elif profile == "new_unknown":
        age = rng.uniform(0, 40)
        rel = rng.randint(1, 3)
        maint = rng.randint(0, 1)
        desc = int(rng.lognormvariate(5, 1.5))
        wheel = rng.random() < 0.5
        repo = rng.random() < 0.4
    else:  # malicious
        age = rng.uniform(0, 120) if rng.random() < 0.85 else rng.uniform(120, 1500)
        rel = rng.randint(1, 4) if rng.random() < 0.85 else rng.randint(4, 20)
        maint = 0 if rng.random() < 0.4 else 1
        desc = int(rng.lognormvariate(4.5, 1.6))
        wheel = rng.random() < 0.35
        repo = rng.random() < 0.2
    first = NOW - timedelta(days=age)
    return PackageMeta(
        name=name, exists=True, first_release=first, last_release=NOW - timedelta(days=age * rng.random()),
        release_count=rel, maintainer_count=maint, description_len=desc, has_wheel=wheel,
        repository=f"github.com/x/{name}" if repo else None,
    )


@dataclass
class Sample:
    name: str
    base: str
    label: int
    x: list[float]


def build_dataset(seed: int = 7, per_base: int = 3) -> list[Sample]:
    rng = random.Random(seed)  # noqa: S311 - 재현 가능한 데이터셋 생성용 (보안 용도 아님)
    pop = popular_packages()
    samples: list[Sample] = []
    for p in pop:
        samples.append(Sample(p, p, 0, feature_vector(name_features(p), _meta(rng, p, "legit"), NOW)))
        for _ in range(per_base):
            n = _mutate(p, rng)
            if n == p or n in pop:
                continue
            nf = name_features(n, popular=pop)
            if rng.random() < 0.8:
                samples.append(Sample(n, p, 2, feature_vector(nf, _meta(rng, n, "malicious"), NOW)))
            else:
                # 이름은 비슷하지만 오래되고 활발한 정상 프로젝트 → 사람이 확인해야 할 '주의'
                samples.append(Sample(n, p, 1, feature_vector(nf, _meta(rng, n, "legit"), NOW)))
    for _ in range(len(pop)):
        n = _random_name(rng)
        if any(osa_distance(n, p, 2) <= 2 for p in pop):
            continue
        nf = name_features(n, popular=pop)
        if rng.random() < 0.7:
            samples.append(Sample(n, n, 0, feature_vector(nf, _meta(rng, n, "legit_small"), NOW)))
        else:
            samples.append(Sample(n, n, 1, feature_vector(nf, _meta(rng, n, "new_unknown"), NOW)))
    return samples


def split(samples: list[Sample], test_ratio: float = 0.3, seed: int = 7) -> tuple[list[Sample], list[Sample]]:
    bases = sorted({s.base for s in samples})
    rng = random.Random(seed)  # noqa: S311 - 재현 가능한 데이터셋 생성용 (보안 용도 아님)
    rng.shuffle(bases)
    test_bases = set(bases[: int(len(bases) * test_ratio)])
    return [s for s in samples if s.base not in test_bases], [s for s in samples if s.base in test_bases]


def train_linear(train: list[Sample], epochs: int = 3000, lr: float = 0.5, l2: float = 1e-3) -> LinearModel:
    import numpy as np

    X = np.array([s.x for s in train], dtype=float)
    y = np.array([s.label for s in train])
    k, d = len(LABELS), X.shape[1]
    W = np.zeros((k, d))
    b = np.zeros(k)
    Y = np.eye(k)[y]
    # 클래스 불균형 보정
    cw = len(y) / (k * np.bincount(y, minlength=k).clip(min=1))
    sw = cw[y][:, None]
    for _ in range(epochs):
        z = X @ W.T + b
        z -= z.max(axis=1, keepdims=True)
        p = np.exp(z)
        p /= p.sum(axis=1, keepdims=True)
        g = (p - Y) * sw / len(X)
        W -= lr * (g.T @ X + l2 * W)
        b -= lr * g.sum(axis=0)
    return LinearModel(W.round(5).tolist(), b.round(5).tolist())


def train_keras(train: list[Sample], out_path: str) -> str:
    """TensorFlow(Keras) 분류 모델 학습 → .keras 저장 + SHA-256 사이드카."""
    import hashlib
    from pathlib import Path

    import keras
    import numpy as np

    X = np.array([s.x for s in train], dtype="float32")
    y = np.array([s.label for s in train])
    model = keras.Sequential(
        [
            keras.Input(shape=(len(FEATURE_NAMES),)),
            keras.layers.Dense(32, activation="relu"),
            keras.layers.Dropout(0.1),
            keras.layers.Dense(16, activation="relu"),
            keras.layers.Dense(len(LABELS), activation="softmax"),
        ]
    )
    model.compile(optimizer="adam", loss="sparse_categorical_crossentropy", metrics=["accuracy"])
    counts = np.bincount(y, minlength=len(LABELS)).clip(min=1)
    model.fit(X, y, epochs=60, batch_size=32, verbose=0,
              class_weight={i: len(y) / (len(LABELS) * c) for i, c in enumerate(counts)})
    p = Path(out_path)
    model.save(p)
    digest = hashlib.sha256(p.read_bytes()).hexdigest()
    p.with_suffix(".sha256").write_text(f"{digest}  {p.name}\n")
    return digest


def evaluate(model, test: list[Sample]) -> dict:
    preds = []
    for s in test:
        pr = model.predict_proba(s.x)
        preds.append(max(range(len(pr)), key=lambda i: pr[i]))
    labels = [s.label for s in test]
    out: dict = {"n": len(test)}
    f1s = []
    for c, name in enumerate(LABELS):
        tp = sum(1 for p, t in zip(preds, labels) if p == c and t == c)
        fp = sum(1 for p, t in zip(preds, labels) if p == c and t != c)
        fn = sum(1 for p, t in zip(preds, labels) if p != c and t == c)
        prec = tp / (tp + fp) if tp + fp else 0.0
        rec = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
        f1s.append(f1)
        out[name] = {"precision": round(prec, 4), "recall": round(rec, 4), "f1": round(f1, 4), "support": tp + fn}
    out["macro_f1"] = round(sum(f1s) / len(f1s), 4)
    # 위험 탐지 관점 (주의+차단 = 양성) 이진 F1
    tp = sum(1 for p, t in zip(preds, labels) if p > 0 and t > 0)
    fp = sum(1 for p, t in zip(preds, labels) if p > 0 and t == 0)
    fn = sum(1 for p, t in zip(preds, labels) if p == 0 and t > 0)
    out["risk_detection_f1"] = round(2 * tp / (2 * tp + fp + fn), 4) if tp else 0.0
    out["accuracy"] = round(sum(1 for p, t in zip(preds, labels) if p == t) / len(test), 4)
    return out



def train_and_save(out_path: str, backend: str = "linear", seed: int = 7) -> dict:
    """데이터셋 생성 → 학습 → 평가. 평가 결과(dict)를 반환하고 모델 메타에 기록한다."""
    samples = build_dataset(seed=seed)
    train, test = split(samples, seed=seed)
    if backend == "keras":
        from trustchain.packages.classifier import KerasModel

        train_keras(train, out_path)
        model = KerasModel(out_path)
        report = evaluate(model, test)
    else:
        model = train_linear(train)
        report = evaluate(model, test)
        model.meta = {"trained_at": NOW.isoformat(), "seed": seed, "n_train": len(train), "eval": report,
                      "dataset": "trustchain synthetic typosquat set v1 (base-name split 70/30)"}
        model.save(out_path)
    return report
