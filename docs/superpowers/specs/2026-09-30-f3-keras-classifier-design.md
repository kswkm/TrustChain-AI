# F3 패키지 위험 분류 : TensorFlow(Keras) 모델 기본 적용 설계

- 작성일 : 2026-09-30
- 상태 : 설계 승인됨, 구현 계획 작성 전

## 1. 배경과 목표

제출한 개발기획서(2-4 F3, 2-5 (2))는 "메타데이터 특징으로 TensorFlow(Keras) 분류 모델을 학습해 정상/주의/차단 세 단계로
판정하고 판정 근거를 보여준다"고 명시한다. 기획서는 허위 기재가 없어야 하고 서류심사의 기준이 된다.

현재 구현은 다르다.

- Keras 학습 경로(`train_keras`, `trustchain model train --backend keras`)는 있으나 학습·탑재된 `.keras` 모델이 없다.
- 판정은 항상 순수 파이썬 선형 모델(`LinearModel.load_default()`, `checker.py`)로 한다.
- README 의 F1 0.995 는 선형 모델 수치다.
- CI 게이트(`trustchain-ci.yml`)는 TensorFlow 없이 설치된다.

**목표** : 기획서대로 Keras 모델로 학습·판정하고, 정량 목표(F1 0.9 이상)를 Keras 모델로 측정해 보고한다.

**제약** : 기획서 2-1 의 "개발자 PC 에서 커밋할 때 점검"(pre-commit)은 가벼워야 한다. TensorFlow(수백 MB)를 코어 의존성으로
만들지 않는다.

## 2. 모델 선택

`classifier.py` 에 `load_default_model()` 을 두고 `PackageChecker` 가 이를 사용한다.

| 조건 | 판정 모델 |
|---|---|
| `TRUSTCHAIN_PKG_MODEL` 미설정, `keras` import 가능 | Keras (`trustchain/data/package_model.keras`) |
| `TRUSTCHAIN_PKG_MODEL` 미설정, `keras` import 불가 | 선형 모델 (`package_model.json`) |
| `TRUSTCHAIN_PKG_MODEL=keras`, `keras` import 불가 | 오류 (`RuntimeError`, 설치 안내 포함) |
| `TRUSTCHAIN_PKG_MODEL=linear` | 선형 모델 |
| 그 밖의 값 | 오류 (`ValueError`) |

- **무결성** : 탑재 모델의 SHA-256 은 `classifier.py` 의 상수 `KERAS_MODEL_SHA256` 으로 고정한다. 불일치 시 선형 모델로
  대체하지 않고 오류로 중단한다(fail-closed). 로드는 `keras.saving.load_model(..., safe_mode=True, compile=False)`.
  사용자가 경로를 지정하는 기존 `KerasModel(path)` 의 사이드카(`.sha256`) 검증은 그대로 유지한다.
- **판정 모델 표시** : 모델 객체에 `backend` 이름("TensorFlow(Keras)" / "경량 선형 모델")을 두고, `Prediction` 과
  패키지 판정 결과(`PackageVerdict.to_dict()`)에 `model` 필드로 싣는다. CLI 패키지 판정 출력에 한 줄로 표시한다.

## 3. 학습과 평가

- **환경** : Docker `python:3.11-slim` + `tensorflow-cpu==2.18.0` (MNIST 데모 CI 와 같은 버전).
  `trustchain model train --backend keras --out src/trustchain/data/package_model.keras`.
- **재현성** : `train_keras()` 에서 `keras.utils.set_random_seed(seed)` 를 호출한다. 데이터셋과 분할은 선형 모델과 같다
  (`build_dataset(seed=7)`, 기반 이름 기준 70/30 분할) — 두 모델을 같은 평가셋으로 비교한다.
- **평가 기록** : `.keras` 파일에는 메타를 둘 수 없으므로 `package_model.keras.json` 에
  `trained_at`, `seed`, `n_train`, `dataset`, `tensorflow`·`keras` 버전, `sha256`, `eval` 을 기록한다.
  `train_and_save(backend="keras")` 가 이 파일을 쓰고, 기존 `.sha256` 사이드카도 계속 쓴다.
- **추론 속도** : `KerasModel.explain()` 은 특징을 하나씩 0 으로 바꾼 12 개 입력과 원본을 한 번의 배치 추론(13 행)으로
  계산한다. `predict_proba()` 는 `model.predict` 대신 `model(x, training=False)` 직접 호출을 쓴다.
- **성능 기준** : Keras 모델의 위험 탐지 F1 이 0.9 이상이면 수치를 그대로 보고한다. 0.9 미만이면 구현을 멈추고 보고한다.

## 4. CI · 패키징 · 문서

- `trustchain-ci.yml` 보안 스캔 게이트 : 설치에 `tensorflow-cpu==2.18.0` 추가, `TRUSTCHAIN_PKG_MODEL=keras` 설정.
- `pyproject.toml` package-data 에 `data/*.keras`, `data/*.keras.json`, `data/*.sha256` 추가.
- 플랫폼 이미지(수집 API·대시보드)는 패키지 판정을 하지 않으므로 TensorFlow 를 넣지 않는다.
- README 검증 결과 표 : F1 을 Keras 수치로 교체하고, 선형 모델 수치는 "경량 대체 모델(TensorFlow 미설치 환경)"로 병기.
  판정 모델 선택 규칙을 설명한다. `docs/evaluation.md` 도 같은 기준으로 갱신한다.

## 5. 테스트

TensorFlow 없이 실행 (로컬 Python 3.13, CI test 잡) :

1. 탑재 `.keras` 파일의 SHA-256 이 `KERAS_MODEL_SHA256` 과 일치한다.
2. `keras` import 가 불가하면 `load_default_model()` 이 선형 모델을 돌려준다.
3. `TRUSTCHAIN_PKG_MODEL=keras` 이고 `keras` 가 없으면 `RuntimeError`.
4. 해시가 다르면 오류 (선형 모델로 대체하지 않음).
5. 패키지 판정 결과에 `model` 필드가 있다.

TensorFlow 가 있을 때만 실행 (`pytest.importorskip("keras")`, 학습 Docker 컨테이너에서 확인) :

6. `load_default_model()` 이 Keras 모델을 돌려주고 판정이 동작한다.
7. 평가셋 위험 탐지 F1 ≥ 0.9.
8. 배치 `explain()` 결과가 특징별 개별 추론 결과와 같다.

## 6. 범위 밖

- 학습 데이터셋 자체의 변경(실측 라벨셋 추가)은 별도 작업.
- 플랫폼 이미지·대시보드 변경 없음.
- 선형 모델 재학습 없음 (기존 `package_model.json` 유지).
