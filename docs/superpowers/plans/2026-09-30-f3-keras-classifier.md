# F3 Keras 분류 모델 기본 적용 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 패키지 위험 판정(F3)을 TensorFlow(Keras) 모델로 학습·탑재·판정하고, TensorFlow 가 없는 환경에서만 선형 모델로 대체한다.

**Architecture:** `classifier.py` 의 `load_default_model()` 이 환경변수·keras 설치 여부로 모델을 고르고, 탑재 `.keras` 는 코드 상수
SHA-256 으로 검증한다. 모델은 Docker(TF 2.18)에서 학습해 `trustchain/data/` 에 넣는다. CI 게이트는 Keras 판정을 강제한다.

**Tech Stack:** Python 3.11, tensorflow-cpu 2.18.0 (Keras 3), pytest, Docker, GitHub Actions

**Spec:** `docs/superpowers/specs/2026-09-30-f3-keras-classifier-design.md`

## Global Constraints

- TensorFlow 는 코어 의존성에 넣지 않는다 (`[ml]` extra, CI 게이트에서만 설치).
- 학습·TF 테스트 환경 : `python:3.11-slim@sha256:e41613d42d4891e4930f79523f93f81bbc7632584ec65e36ab055f41a800b41e` + `tensorflow-cpu==2.18.0`.
- 데이터셋·분할 : `build_dataset(seed=7)`, `split(samples, seed=7)` (선형 모델과 동일).
- 환경변수 : `TRUSTCHAIN_PKG_MODEL` ∈ {미설정, `keras`, `linear`}. 그 밖의 값은 `ValueError`.
- 표시 이름 : Keras = `"TensorFlow(Keras)"`, 선형 = `"경량 선형 모델"`.
- 탑재 파일 : `src/trustchain/data/package_model.keras`, `package_model.keras.json`, `package_model.sha256`.
- 해시 불일치는 오류로 중단한다 (선형 모델로 대체하지 않음).
- 성능 기준 : Keras 위험 탐지 F1 ≥ 0.9. 미달 시 Task 2 에서 멈추고 사용자에게 보고.
- 로컬 개발 환경(Windows, Python 3.13)에는 TensorFlow 가 없다. TF 테스트는 아래 Docker 명령으로 실행한다.

TF 테스트 이미지 (1회 빌드, Git Bash) :

```bash
printf 'FROM python:3.11-slim@sha256:e41613d42d4891e4930f79523f93f81bbc7632584ec65e36ab055f41a800b41e\nRUN pip install --no-cache-dir tensorflow-cpu==2.18.0 pytest\n' | docker build -t trustchain-tf -
```

TF 컨테이너 실행 (이하 `TFRUN <명령>`) :

```bash
MSYS_NO_PATHCONV=1 docker run --rm -v "$(pwd -W):/src" -w /src trustchain-tf sh -c "pip install -q -e '.[dev]' && <명령>"
```

## Review Focus

1. keras 가 설치됐지만 Keras 2 (TF < 2.16) 인 환경 → 자동 모드는 선형 모델로 대체해야 한다 (Keras 3 형식 로드 실패로 CLI 가 죽으면 안 됨). → Task 3 테스트 `test_keras2_falls_back_to_linear`.
2. 개발자 PC 에 keras 가 있으면 기존 패키지 테스트가 Keras 로 판정돼 결과가 흔들린다 → `tests/conftest.py` autouse 픽스처로 `TRUSTCHAIN_PKG_MODEL=linear` 고정, Keras 테스트만 해제. → Task 3.
3. Keras 로 판정해도 공격 시나리오 1·2 는 차단, 인기 패키지(`requests`)는 정상이어야 한다. → Task 3 검증 단계 (`run_all.py --offline`, Keras 강제).
4. 설치된 휠(비 editable)에 `.keras` 파일이 빠지면 CI 게이트가 모델을 못 찾는다. → Task 3 휠 내용 검증 단계.
5. TF 로그가 stdout 에 섞이면 `trustchain pkg --format json` 출력이 깨진다 → keras import 전 `TF_CPP_MIN_LOG_LEVEL=2` 기본값. → Task 3 검증 단계 (JSON 파싱).

---

### Task 1: Keras 학습 재현성 · 평가 기록 · 추론 배치화

**Files:**
- Modify: `src/trustchain/packages/training.py` (`train_keras`, `train_and_save`)
- Modify: `src/trustchain/packages/classifier.py` (`KerasModel.predict_proba`, `KerasModel.explain`)
- Test: `tests/test_classifier.py` (신규)

**Interfaces:**
- Produces: `train_keras(train: list[Sample], out_path: str, seed: int = 7) -> str` (SHA-256 반환, `.sha256` 사이드카 작성)
- Produces: `train_and_save(out_path, backend="keras", seed=7)` 가 `<out_path>.json` (예: `package_model.keras.json`) 에
  `{"trained_at", "seed", "n_train", "dataset", "tensorflow", "keras", "sha256", "eval"}` 기록. `dataset` 문자열은 선형 모델과 동일.
- Produces: `KerasModel.explain(x, cls_idx, top=3)` — 원본 + 특징 12개를 0 으로 바꾼 입력, 13행 한 번의 추론.

- [ ] **Step 1: TF 전용 실패 테스트 작성** (`tests/test_classifier.py`, 모듈 안 Keras 테스트는 `keras = pytest.importorskip("keras")` 를 함수 안에서 호출)

```python
def test_keras_explain_batch_matches_single(tmp_path):
    keras = pytest.importorskip("keras")
    samples = build_dataset(seed=7); train, test = split(samples, seed=7)
    train_keras(train[:300], str(tmp_path / "m.keras"), seed=7)
    m = KerasModel(tmp_path / "m.keras")
    x = test[0].x
    base = m.predict_proba(x)
    expected = []
    for i in range(len(x)):
        x2 = list(x); x2[i] = 0.0
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
    assert meta["eval"] == rep and meta["seed"] == 7 and meta["sha256"] == (tmp_path / "p.sha256").read_text().split()[0]
    assert {"trained_at", "n_train", "dataset", "tensorflow", "keras"} <= meta.keys()
```

- [ ] **Step 2: TF 컨테이너에서 실패 확인**

Run: `TFRUN "pytest -q tests/test_classifier.py"`
Expected: FAIL (`_contributions` 없음, `train_keras()` 의 `seed` 인자 없음, `p.keras.json` 없음)

- [ ] **Step 3: 구현**
  - `train_keras` : 학습 전 `keras.utils.set_random_seed(seed)`.
  - `train_and_save` keras 분기 : 평가 후 `Path(out_path + ".json")` 에 메타 기록 (`tensorflow.__version__`, `keras.__version__`, `NOW.isoformat()`).
  - `KerasModel._contributions(x, cls_idx) -> list[float]` : 13행 배치 추론으로 `base[cls] - masked_i[cls]` 목록. `explain()` 은 이를 정렬해 기존과 같은 규칙(`> 0.02`, 상위 `top`)으로 반환.
  - `KerasModel.predict_proba` : `self.model(np.array([x], dtype="float32"), training=False)` 결과를 float 리스트로.

- [ ] **Step 4: 통과 확인**

Run: `TFRUN "pytest -q tests/test_classifier.py"` → PASS. 로컬 `pytest -q` → 기존 테스트 전부 PASS, Keras 테스트는 SKIP.

- [ ] **Step 5: Commit** — `feat(packages): Keras 학습 재현성·평가 메타 기록, 설명 추론 배치화`

---

### Task 2: Keras 모델 학습 · 탑재 (Docker)

**Files:**
- Create: `src/trustchain/data/package_model.keras`, `package_model.keras.json`, `package_model.sha256`

**Interfaces:**
- Consumes: Task 1 의 `train_and_save(..., backend="keras", seed=7)`
- Produces: 탑재 모델 SHA-256 (Task 3 의 `KERAS_MODEL_SHA256` 값), 평가 지표 (Task 4 문서 수치)

- [ ] **Step 1: 학습**

Run: `TFRUN "trustchain model train --backend keras --out src/trustchain/data/package_model.keras"`
Expected: 평가 JSON 출력, 3개 파일 생성.

- [ ] **Step 2: 성능 기준 확인** — 출력의 `risk_detection_f1` ≥ 0.9. **미달이면 여기서 멈추고 수치를 사용자에게 보고한다.**

- [ ] **Step 3: 재현 확인** — 같은 명령으로 임시 경로에 다시 학습해 `eval` 이 동일한지 확인 (SHA-256 은 달라도 됨; 탑재본은 Step 1 결과 유지).

- [ ] **Step 4: Commit** — `feat(packages): TensorFlow(Keras) 패키지 위험 분류 모델 탑재` (SHA-256·F1 을 본문에 기재)

---

### Task 3: 기본 모델 선택 · 무결성 · 판정 모델 표시

**Files:**
- Modify: `src/trustchain/packages/classifier.py` (상수, `backend`, `Prediction.model`, `load_default_model`)
- Modify: `src/trustchain/packages/checker.py:84,131` 및 `PackageVerdict`
- Modify: `src/trustchain/cli.py` (`cmd_pkg` 텍스트 출력), `pyproject.toml` (package-data)
- Modify: `tests/conftest.py` (autouse 픽스처), Test: `tests/test_classifier.py`

**Interfaces:**
- Consumes: Task 2 의 SHA-256
- Produces: `KERAS_MODEL_FILE = "package_model.keras"`, `KERAS_MODEL_SHA256 = "<Task 2 값>"`
- Produces: `LinearModel.backend = "경량 선형 모델"`, `KerasModel.backend = "TensorFlow(Keras)"` (클래스 속성)
- Produces: `Prediction.model: str = ""` — `predict()` 가 `model.backend` 로 채움
- Produces: `load_default_model() -> LinearModel | KerasModel`
- Produces: `PackageVerdict.model: str = ""`, `to_dict()["model"]`
- Produces: `PackageChecker(model: LinearModel | KerasModel | None = None)` — 기본값은 `load_default_model()`

- [ ] **Step 1: 실패 테스트 작성** (`tests/test_classifier.py`, TF 없이 동작)

```python
def test_bundled_keras_hash_matches_constant():
    data = resources.files("trustchain.data").joinpath(KERAS_MODEL_FILE).read_bytes()
    assert hashlib.sha256(data).hexdigest() == KERAS_MODEL_SHA256

def test_auto_without_keras_uses_linear(monkeypatch):
    monkeypatch.delenv("TRUSTCHAIN_PKG_MODEL", raising=False)
    monkeypatch.setitem(sys.modules, "keras", None)          # import keras → ImportError
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
    assert v.to_dict()["model"] == "경량 선형 모델"          # conftest 가 linear 로 고정

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
```

`tests/conftest.py` : autouse 픽스처가 `TRUSTCHAIN_PKG_MODEL=linear` 설정. Keras 테스트(`test_default_model_is_keras_when_available`)는 `monkeypatch.delenv` 로 해제.

- [ ] **Step 2: 실패 확인** — 로컬 `pytest -q tests/test_classifier.py` → FAIL (`load_default_model` 등 없음)

- [ ] **Step 3: 구현**
  - `load_default_model()` : 환경변수 검증 → `linear` 면 `LinearModel.load_default()`. 아니면 `os.environ.setdefault("TF_CPP_MIN_LOG_LEVEL", "2")` 후 `import keras`;
    ImportError 또는 `keras.__version__` 주 버전 < 3 이면 — 강제(`keras`)는 `RuntimeError("... pip install tensorflow-cpu==2.18.0 ...")`, 자동은 선형 모델.
    그 외 `importlib.resources.as_file()` 로 탑재 경로를 얻어 `KerasModel(path, expected_sha256=KERAS_MODEL_SHA256)`. 해시 오류(`ValueError`)는 잡지 않는다.
  - `KerasModel.__init__` : 해시 검증을 keras import **이전**에 수행 (현재 순서 유지 — 해시 테스트가 가짜 keras 로 통과하려면 필수).
  - `checker.py` : 기본 모델을 `load_default_model()` 로, 판정 시 `v.model = pred.model`.
  - `cli.py` `cmd_pkg` 텍스트 출력 : 확률 줄 다음에 `   판정 모델 : {v.model}`.
  - `pyproject.toml` package-data : `"data/*.keras"`, `"data/*.keras.json"`, `"data/*.sha256"` 추가.

- [ ] **Step 4: 통과 확인**
  - 로컬 `pytest -q` → 전부 PASS (Keras 전용 SKIP). `ruff check src tests` → 통과.
  - `TFRUN "pytest -q tests/test_classifier.py tests/test_packages.py"` → 전부 PASS (Keras 전용 포함).
  - Review Focus 5 : `TFRUN "TRUSTCHAIN_PKG_MODEL=keras trustchain pkg reqeusts requests --format json | python -c 'import json,sys; print([p[\"model\"] for p in json.load(sys.stdin)[\"packages\"]])'"` → `['TensorFlow(Keras)', 'TensorFlow(Keras)']` (JSON 파싱 성공 = stdout 에 TF 로그 없음). 종료 코드 2(차단)는 정상.
  - Review Focus 4 : `pip wheel . --no-deps -w dist -q && python -c "import zipfile,glob; n=zipfile.ZipFile(glob.glob('dist/trustchain_ai-*.whl')[0]).namelist(); assert 'trustchain/data/package_model.keras' in n and 'trustchain/data/package_model.keras.json' in n"` → 오류 없음. (`dist/` 는 커밋하지 않음)
  - Review Focus 3 : `TFRUN "TRUSTCHAIN_PKG_MODEL=keras python scenarios/run_all.py --offline"` → `실행 5종 중 차단 5종`, 시나리오 2 근거에 `분류 모델 판정 '차단'`.

- [ ] **Step 5: Commit** — `feat(packages): TensorFlow 설치 환경에서 Keras 모델로 기본 판정, 해시 고정·판정 모델 표시`

---

### Task 4: CI 게이트 Keras 강제 · 문서 수치 갱신

**Files:**
- Modify: `.github/workflows/trustchain-ci.yml` ("TrustChain · Semgrep · Bandit 설치" · "보안 스캔 게이트" 단계)
- Modify: `README.md` (검증 결과 표·각주), `docs/evaluation.md`

**Interfaces:**
- Consumes: Task 2 평가 지표 (`package_model.keras.json` 의 `eval`), 선형 모델 지표 (`package_model.json` 의 `meta.eval`)

- [ ] **Step 1: 워크플로우 수정** — 설치 줄에 `tensorflow-cpu==2.18.0` 추가, 게이트 단계 `env: TRUSTCHAIN_PKG_MODEL: keras`.
- [ ] **Step 2: 워크플로우 문법 확인** — `python -c "import yaml; yaml.safe_load(open('.github/workflows/trustchain-ci.yml', encoding='utf-8'))"` 오류 없음.
- [ ] **Step 3: README 갱신** — F1 행 결과를 Keras 수치(위험 탐지 F1, 3-클래스 macro F1)로 교체하고 "TensorFlow(Keras) 분류 모델" 명시, 각주에 경량 선형 모델 수치와 선택 규칙(TF 설치 시 Keras, 미설치 시 선형, CI 게이트는 Keras 강제) 추가. 재현 명령 `trustchain model eval --out src/trustchain/data/package_model.keras` (TF 필요).
- [ ] **Step 4: `docs/evaluation.md`** — 분류 모델 절을 같은 수치·규칙으로 갱신.
- [ ] **Step 5: Commit** — `ci,docs: CI 게이트 Keras 판정 강제, 분류 모델 평가 수치 갱신`
- [ ] **Step 6: 원격 CI 확인 (push 는 사용자 승인 후)** — push 후 `ci` 워크플로우의 두 "보안 스캔 게이트" 잡이 성공하고 로그에 Keras 판정이 쓰였는지 확인.
