# F3 패키지 분류 모델 : 실제 PyPI 데이터 검증 설계

- 작성일 : 2026-10-01
- 상태 : 설계 승인됨, 구현 계획 작성 전

## 1. 배경과 목표

`docs/evaluation.md` 1절의 분류 모델 수치(Keras 위험 탐지 F1 0.999)는 합성 평가셋 기준이며, 같은 절에 "실제 PyPI 에서의 성능을
보장하지 않는다"는 한계가 적혀 있다.

**목표** : 현재 탑재된 모델(Keras, 경량 선형)을 바꾸지 않고, 실제 악성·정상 PyPI 패키지로 성능을 측정해 재현 가능하게 문서화한다.
수치가 낮게 나와도 그대로 보고한다. 모델 재학습·재탑재는 범위 밖이다.

## 2. 제약과 평가 방식

- 실제 악성 라벨은 OSV PyPI 덤프의 `MAL-` 항목(2026-10-01 기준 11,792건, OpenSSF malicious-packages)에서 얻는다.
  이 중 550건은 출처가 `typosquatting` 으로 표시했다 — 우리 모델과 독립된 라벨이다.
- 악성 패키지는 보고 후 PyPI 에서 삭제되므로 **공격 당시 메타데이터(특징 12개 중 6개)를 복원할 수 없다**.
- 따라서 측정 가능한 것만 측정한다.
  - **악성 쪽** : 실제 이름으로 이름 특징을 계산하고, 메타데이터는 `None` (기존 "메타데이터 모름 → 중립값" 경로,
    `classifier.meta_vector`). 메타데이터 신호를 쓰지 않으므로 탐지율은 **보수적(낮은 쪽)** 수치다.
  - **정상 쪽** : 현재 PyPI 에 존재하는 실제 패키지를 실제 메타데이터로 판정한다 (특징 12개 모두).
- 공격 당시 메타데이터를 가정으로 채우는 방식은 합성 데이터의 가정을 그대로 재사용하게 되어 독립 검증이 아니므로 쓰지 않는다.

## 3. 데이터 스냅샷 (`eval/pkg_real/`, 커밋)

`trustchain model real-data` 가 한 번 수집해 저장한다. 이후 평가는 네트워크 없이 이 파일만 사용한다.

| 파일 | 내용 |
|---|---|
| `malicious.jsonl` | OSV PyPI 덤프의 `MAL-` 항목 : `name`(정규화), `osv_id`, `published`, `typosquat`(요약·상세에 "typosquat" 포함 여부) |
| `benign.jsonl` | 정상 표본 : `name`, `source`(`rank` / `random`), `rank`(있으면), `meta`(PackageMeta 필드 직렬화) |
| `manifest.json` | 수집 시각(`collected_at`), seed, OSV 덤프 URL·SHA-256·`MAL-` 건수, 인기 순위 목록 URL·`last_update`·SHA-256, 제외 건수(사유별) |

- **정상 표본** (seed 7)
  - `rank` 1,000개 : hugovk top-pypi-packages(30일) 순위 1,000~15,000위에서 무작위 추출.
  - `random` 1,000개 : PyPI Simple API(`https://pypi.org/simple/`, JSON) 전체 목록에서 무작위 추출.
  - 제외 : OSV 악성 목록에 있는 이름, `popular_packages.txt` 의 409개, 존재하지 않음(`exists=False`), 조회 오류(`lookup_error`),
    최신 버전 yanked. 제외되면 같은 원천에서 다음 후보를 뽑아 목표 개수를 채운다.
- 메타데이터 조회는 기존 `PyPIClient`(캐시 HTTP)를 사용한다. 네트워크 오류는 중단하고, 재실행 시 캐시로 이어서 받는다.
- **시점 고정** : 나이 특징(`young_package`)이 시간에 따라 변하지 않도록, 평가 시 `now = manifest.collected_at` 을 쓴다.

## 4. 평가 (`trustchain model eval-real`)

- 판정 : 기존 `training.evaluate` 와 같은 경로(`feature_vector` → `predict_proba`). 예측이 "주의" 또는 "차단"이면 탐지(양성).
- 이름 특징 : `typosquat.name_features(name)` (기존 판정과 동일).
- 출력(JSON) :
  - `model` : 판정 모델 표시 이름
  - `malicious.typosquat` / `malicious.all` : `n`, `detection_rate`(주의+차단), `block_rate`(차단만)
  - `benign.rank` / `benign.random` / `benign.all` : `n`, `false_positive_rate`(주의+차단), `block_fp_rate`(차단만)
  - `precision_at_prevalence` : 악성 비율 1% · 0.1% · 0.01% 가정에서 `p·TPR / (p·TPR + (1−p)·FPR)`.
    TPR 은 `malicious.typosquat.detection_rate`, FPR 은 `benign.all.false_positive_rate`.
  - `conditions` : 악성 쪽 메타데이터 미사용, 스냅샷 수집 시각
- 모델 선택 : `--out` 규칙은 기존 `model eval` 과 같다 (`.keras` 면 Keras, 아니면 선형). 문서에는 두 모델 결과를 모두 싣는다
  (Keras 는 TF Docker 컨테이너에서 실행).
- 스냅샷이 없으면 `trustchain model real-data` 실행 안내와 함께 종료 코드 2.

## 5. 코드 구성

- 신규 `src/trustchain/packages/realeval.py`
  - `load_osv_malicious(zip_path) -> list[dict]`
  - `sample_benign(rank_names, all_names, exclude, client, n_rank, n_random, seed) -> (list[dict], dict 제외 건수)`
  - `collect(out_dir, ...)` : 다운로드·표본·메타데이터 수집·스냅샷 저장
  - `evaluate_real(model, snapshot_dir) -> dict`
  - `precision_at(tpr, fpr, prevalence) -> float`
- `PackageMeta` 직렬화/역직렬화(`to_json` / `from_json`, datetime 은 ISO 8601)를 `pypi.py` 에 추가.
- `cli.py` : `model` 의 `action` 선택지에 `real-data`, `eval-real` 추가, `--data-dir`(기본 `eval/pkg_real`).
- 기존 `training.py` 는 변경하지 않는다.

## 6. 테스트 (모두 오프라인)

- OSV 파싱 : 작은 픽스처 zip(일반 취약점 + `MAL-` 2건, 그중 1건 typosquatting 표기) → `MAL-` 만, 태그 정확.
- 정상 표본 : 가짜 클라이언트로 제외 규칙(악성·인기·없음·조회 오류·yanked)과 목표 개수 보충, seed 재현성.
- `PackageMeta` 직렬화 왕복.
- 지표 : `precision_at` 수식, 탐지율·오탐률 계산.
- 종단 : 작은 스냅샷 픽스처 + 선형 모델로 `eval-real` 출력 키·값 범위 확인, 스냅샷 없음 → 종료 코드 2.

## 7. 문서

- `docs/evaluation.md` 1절 : "한계" 문단을 실측 결과 표(두 모델)와 측정 조건으로 교체. 악성 쪽은 이름 특징만 사용한 보수적
  수치이고, 정상 쪽 오탐률은 실제 메타데이터 기준임을 명시. 재현 명령 기재.
- README 검증 결과 각주에 실측 요약 한 줄 추가. F1 행(합성 평가셋)은 그대로 둔다.
