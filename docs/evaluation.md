# 정량 평가 (개발기획서 3-4 정량 목표)

모든 수치는 아래 명령으로 재현할 수 있습니다. 측정 조건과 한계를 함께 적습니다.

## 1. 타이포스쿼팅·환각 패키지 탐지 (목표 F1 ≥ 0.9)

```bash
# 기본 판정 모델 : TensorFlow(Keras) (tensorflow-cpu 2.18.0, 학습 기록 src/trustchain/data/package_model.keras.json)
trustchain model eval --out src/trustchain/data/package_model.keras
trustchain model train --backend keras --out m.keras   # 재학습 (seed 7 고정, tensorflow-cpu 2.18.0 + keras 3.15.1 에서 같은 평가 결과 확인)
# 경량 대체 모델 : 다항 로지스틱 회귀 (TensorFlow 미설치 환경)
trustchain model eval                  # src/trustchain/data/package_model.json
trustchain model train --out m.json
```

**TensorFlow(Keras) 분류 모델** (Dense 32 → Dropout 0.1 → Dense 16 → softmax 3, 60 epoch, 클래스 가중치)

| 클래스 | precision | recall | F1 | support |
|---|---|---|---|---|
| 정상 | 0.995 | 1.000 | 0.998 | 198 |
| 주의 | 0.968 | 1.000 | 0.984 | 91 |
| 차단 | 1.000 | 0.986 | 0.993 | 287 |
| **macro F1** | | | **0.991** | 576 |
| **위험 탐지 F1** (주의+차단 vs 정상) | | | **0.999** | |

**경량 선형 모델** (같은 평가셋) : macro F1 0.950, 위험 탐지 F1 0.995 (정상 0.990 · 주의 0.895 · 차단 0.966)

**판정 모델 선택** : TensorFlow(Keras 3)가 설치돼 있으면 Keras 모델, 없으면 경량 선형 모델로 판정합니다(`TRUSTCHAIN_PKG_MODEL=keras|linear` 로 강제).
탑재 Keras 모델은 코드에 고정한 SHA-256 과 일치해야 로드되며(`safe_mode`), 불일치 시 다른 모델로 대체하지 않고 오류로 중단합니다.
CI 게이트는 Keras 판정을 강제합니다.

**평가셋 구성** (`packages/training.py`, seed 7) — 자체 구축 합성 데이터
- 정상 : 인기 패키지 407개(오래됨·배포 이력 많음) + 인기 목록과 편집거리 3 이상인 임의 이름의 소규모 정상 패키지
- 차단 : 인기 패키지 이름에 공개 보고된 위장 패턴(키보드 인접 치환, 0/o·l/1 치환, 문자 누락·중복·자리바꿈, `python-` 접두사·`-py` 접미사, 구분자 변경)을 적용하고
  악성 패키지의 전형적 메타데이터(최근 등록, 배포 1~4회, 설명 짧음, 휠 없음, 저장소 없음)를 표본 추출. 일부(15%)는 오래되었거나 배포가 많은 경우도 섞음
- 주의 : 위장 이름이지만 메타데이터는 정상인 경우, 이름은 무관하지만 새로 등록된 무명 패키지
- 학습/평가는 **원본 인기 패키지 단위로 70/30 분리**해 같은 이름의 변형이 양쪽에 들어가지 않게 함

위 수치는 메타데이터 분포를 가정해 만든 합성 데이터 기준입니다. 실제 PyPI 데이터로 따로 검증한 결과는 아래와 같습니다.
환각 패키지(PyPI 에 존재하지 않음)는 모델이 아니라 규칙으로 판정하므로 PyPI 조회가 성공하면 탐지 누락이 없습니다.

### 실제 PyPI 데이터 검증

```bash
trustchain model eval-real                                                    # 경량 선형 모델 (eval/pkg_real 스냅샷, 네트워크 불필요)
trustchain model eval-real --out src/trustchain/data/package_model.keras      # Keras (TensorFlow 필요)
trustchain model real-data                                                    # 스냅샷 재수집 (네트워크, 수십 분)
```

**데이터** (`eval/pkg_real/`, 2026-10-01 수집, `manifest.json` 에 원천 URL·SHA-256 기록)
- 악성 : OSV PyPI 덤프의 `MAL-` 항목(OpenSSF malicious-packages) 중 철회(withdrawn)되지 않은 **11,768건**, 이 중 보고 본문에
  "typosquat" 이 언급된 **543건**(출처의 정식 분류 필드가 아니라 본문 언급 기준)
- 정상 : 다운로드 순위 1,000~15,000위에서 1,000개 + PyPI 전체 프로젝트(903,503개)에서 무작위 1,000개 (seed 7). 악성 목록 229건,
  인기 목록 406건, 존재하지 않음 18건, 최신 버전 yanked 1건은 제외하고 다시 뽑음

**정상 패키지 실사용 오탐률** (실제 PyPI 메타데이터로 판정, 주의+차단 / 차단만)

| 정상 표본 | TensorFlow(Keras) | 경량 선형 |
|---|---|---|
| 순위 1,000~15,000위 (1,000개) | 5.0% / 1.2% | 10.4% / 0.7% |
| 전체 무작위 (1,000개, 대부분 무명 패키지) | 10.6% / 3.0% | 19.0% / 2.2% |
| **합계 (2,000개)** | **7.8% / 2.1%** | **14.7% / 1.45%** |

**이름 신호** (악성·정상 모두 메타데이터 없이 같은 조건에서 위험 확률 `1−P(정상)` 비교)

| 악성 집합 (정상 2,000개 대비) | 모델 | AUC | 오탐률 1% 에서 탐지율 | 오탐률 5% 에서 탐지율 |
|---|---|---|---|---|
| typosquat 언급 543건 | Keras | 0.563 | 12.9% | 18.2% |
| | 경량 선형 | 0.563 | 12.9% | 18.2% |
| 전체 11,768건 | Keras | 0.499 | 6.8% | 9.95% |
| | 경량 선형 | 0.499 | 6.8% | 10.0% |

**해석과 측정 조건** (아래 건수는 모두 `eval-real` 출력에 포함되어 재현됩니다)
- 악성 패키지는 보고 후 PyPI 에서 삭제되어 공격 당시 메타데이터를 얻을 수 없습니다. 메타데이터가 없으면 모델은 이름과 무관하게 위험으로
  판정합니다 (정상 이름 2,000개를 메타데이터 없이 판정하면 Keras 주의 1,896 · 차단 104, 경량 선형 주의 1,994 · 차단 6, 정상 0).
  그래서 악성 쪽 "탐지율"은 지표로 쓰지 않고 같은 조건의 점수 비교(AUC)만 보고합니다. 실제 판정에서 메타데이터 조회에 실패하면
  경고하는 것은 의도한 안전 동작입니다.
- 이름 신호가 약한 이유 : typosquat 언급 543건 중 인기 패키지(406개)와 편집거리 2 이하인 이름은 **86건(15.8%)** 뿐이고, 나머지는
  덜 알려진 프로젝트 모방(`detecron2`), 단어 조합형 위장(`log-guru`, `telebot-bot-run`), 이름만으로는 위장으로 보기 어려운 이름입니다.
  편집거리 기반 이름 탐지가 다룰 수 있는 범위가 원래 이 정도이며, 오탐률 1% 에서의 탐지율 12.9% 는 그 범위 안에서 나온 값입니다.
  전체 악성의 대부분은 무작위 이름의 악성 코드라 이름 기반 탐지 대상이 아닙니다. 또한 일부 `MAL-` 항목은 정상 패키지의 특정 버전이
  침해된 경우라 이름만으로 판정할 대상이 아닙니다.
- 정상 쪽 오탐은 대부분 "주의"이며, 새로 등록됐거나 배포 이력·설명이 적은 무명 패키지에서 많이 나옵니다(무작위 표본 10.6%).

**개선 시도 (채택하지 않음)** : 비교 대상 인기 패키지 목록을 다운로드 순위 상위 N 개로 넓혀 같은 스냅샷에서 측정했습니다
(탑재 경량 선형 모델, 2026-10-02).

| 인기 목록 크기 | 이름 신호 AUC | 오탐률 1% 에서 탐지율 | 정상 실사용 오탐률 (주의+차단 / 차단) |
|---|---|---|---|
| 현재 406 | 0.563 | 12.9% | 14.7% / 1.45% |
| 1,053 | 0.566 | 12.7% | 18.8% / 2.2% |
| 2,018 | 0.586 | 12.2% | 22.6% / 2.8% |
| 5,006 | 0.636 | 12.5% | 26.8% / 3.2% |

목록을 넓히면 AUC 는 오르지만 같은 오탐률에서의 탐지율은 늘지 않고, 확장 패키지처럼 인기 패키지와 이름이 비슷한 정상 패키지가 많아져
실사용 오탐률이 거의 두 배가 됩니다. 합성 학습 데이터에는 '이름이 비슷한 정상 패키지'가 없어 재학습으로도 해결되지 않으므로 현재 목록을
유지합니다. 단어 조합형 위장(`log-guru`) 특징도 `flask-cors` 같은 정상 확장 패키지와 구분되지 않아 같은 이유로 넣지 않았습니다.

**남은 한계** : 공격 당시 메타데이터(등록 직후·배포 1회·저장소 없음 등)를 포함한 악성 쪽 측정은 아직 없습니다. 이를 위해서는 신규 등록
패키지를 등록 시점에 수집해 두고 이후 `MAL-` 보고와 대조하는 전향적 수집이 필요합니다.

## 2. AI 어시스턴트 검색 정확도 (목표 Recall@5 ≥ 0.8, 리랭킹 전후 비교)

```bash
trustchain eval --offline-models --answers                                   # 외부 모델 없는 기준선
pip install .[ai] && trustchain eval --answers                               # multilingual-e5-small + Cross-encoder + Kiwi + rank_bm25
trustchain eval --answers --osv-dir <OSV PyPI 덤프> --cwe-csv <MITRE CWE CSV>  # 운영 규모 지식베이스
```

평가셋 `eval/rag_eval.jsonl` : 32문항 (KISA 시큐어코딩 요약 19, 공급망 7, OSV 권고문 6).
지식베이스는 두 가지로 측정했습니다 (2026-10-02).
- **내장** : 패키지에 포함된 KISA·CWE 요약·공급망 문서·OSV 샘플 76개 청크
- **운영 규모** : 내장 + OSV PyPI 권고문 14,039건(악성 패키지 보고 `MAL-` 제외, 덤프 SHA-256 `c327e474…`) + MITRE CWE 1000 목록 = **57,337개 청크**
- NVD CVE 권고문(API 2.0 응답 JSON)은 `trustchain kb --nvd-dir` / `trustchain eval --nvd-dir` 로 같은 구조(설명·영향 버전·조치 방법)로
  추가합니다. OSV PyPI 권고문 대부분이 CVE 별칭과 같은 내용을 담고 있어 위 측정에는 NVD 를 따로 넣지 않았습니다.

**실제 모델** (다국어 임베딩 `intfloat/multilingual-e5-small` 384차원, Cross-encoder `cross-encoder/mmarco-mMiniLMv2-L12-H384-v1`,
Kiwi 형태소 분석 + `rank_bm25`, 모델은 HuggingFace 커밋 리비전 고정, 플랫폼 이미지의 해시 고정 의존성으로 실행)

| 단계 | 내장 Recall@5 | 내장 MRR | 운영 규모 Recall@5 | 운영 규모 MRR |
|---|---|---|---|---|
| BM25 (Kiwi) | 0.969 | 0.930 | 0.906 | 0.836 |
| 벡터 (다국어 임베딩) | 1.000 | 0.977 | 0.938 | 0.817 |
| 하이브리드 (RRF) | 1.000 | 0.945 | **0.969** | **0.893** |
| **하이브리드 + 리랭킹** (하이브리드 순위와 Cross-encoder 순위 RRF 결합) | 1.000 | **0.961** | **0.969** | **0.896** |

**외부 모델 없는 기준선** (해싱 임베딩 · 정규식 토크나이저 · 어휘 리랭커)

| 단계 | 내장 Recall@5 | 내장 MRR | 운영 규모 Recall@5 | 운영 규모 MRR |
|---|---|---|---|---|
| BM25 | 0.969 | 0.862 | 0.844 | 0.732 |
| 벡터 (해싱) | 0.969 | 0.823 | 0.469 | 0.378 |
| 하이브리드 (RRF) | 1.000 | 0.896 | 0.844 | 0.724 |
| 하이브리드 + 리랭킹 | 1.000 | 0.912 | 0.875 | 0.776 |

**해석**
- 목표 Recall@5 0.8 은 모든 구성에서 넘었고, 운영 규모(57,337 청크)에서도 실제 모델 하이브리드 검색이 0.969 입니다.
- 하이브리드(RRF)는 운영 규모에서 BM25·벡터 단독보다 높습니다 (실제 모델 MRR 0.836·0.817 → 0.893). 지식베이스가 커질수록 두 검색을 결합한 효과가 커집니다.
- 리랭킹 전후 : 실제 모델 MRR 내장 0.945 → **0.961**, 운영 규모 0.893 → **0.896** (Recall@5 0.969 유지), 기준선 내장 0.896 → 0.912,
  운영 규모 0.724 → 0.776 으로 모든 구성에서 리랭킹 후가 높습니다.
- 리랭킹 방식 개선 과정 : 처음에는 Cross-encoder 점수만으로 후보 30개를 다시 정렬했는데, 운영 규모에서 오히려 낮아졌습니다
  (Recall@5 0.969 → 0.938, MRR 0.893 → 0.870). CVE·패키지명처럼 식별자 중심 질의에서 범용 Cross-encoder 가 정답을 밀어냈기 때문입니다.
  같은 저장 임베딩으로 6가지 방식을 비교한 결과 **하이브리드 순위와 Cross-encoder 순위를 다시 RRF 로 결합**하는 방식만 두 지식베이스
  모두에서 리랭킹 전보다 높았습니다 (제목+본문 입력은 내장 0.969 였지만 운영 규모 0.820 으로 하락, 식별자 일치 가산점은 효과 없음).
  표의 수치는 이 방식을 적용한 제품 코드로 다시 측정한 값입니다.
- 내장 지식베이스에서 실제 벡터 검색 단독(MRR 0.977)이 하이브리드(0.945)보다 높은 것은 문서가 76개로 적어 의미 검색만으로 충분하기 때문입니다.
- 답변 충실도(faithfulness)는 LLM 없이 문장을 발췌하는 기준선에서 1.0 으로, 발췌 방식이라 당연히 높게 나옵니다. LLM 을
  연결하면(`TRUSTCHAIN_LLM_API_KEY`) 같은 지표로 생성형 답변을 평가합니다.
- 평가셋이 32문항으로 작아 1문항 차이가 Recall@5 0.031 에 해당합니다.

## 3. 신규 취약점 영향 서비스 식별 (목표 SBOM 매칭 후 1분 이내 알림)

`tests/test_server_feed.py::test_ingest_flow_trust_score_and_alert_latency` : SBOM 수집 → OSV 매칭 → Alert 생성 → 알림 전송까지를 한 요청 안에서
처리하고 60초 미만을 확인합니다 (가짜 OSV 응답 사용). 피드 모니터는 알림마다 `matched_at`/`notified_at` 과 지연 시간(ms)을 기록합니다.
주기 수집 간격은 `TRUSTCHAIN_FEED_INTERVAL_MIN`(기본 10분)이며, "발표 → 수집" 지연은 이 간격에 좌우됩니다.

## 4. 빌드 신뢰 수준 (목표 SLSA Build L3)

`trustchain-ci.yml` 이 `slsa-framework/slsa-github-generator` 의 `generator_container_slsa3.yml@v2.1.0` 을 호출해 출처 증명을 생성합니다.
Verify Gate 와 Kyverno 정책은 이 빌더 ID 로 만들어진 증명만 허용합니다.

**실행 결과** : 커밋 `c271b15` 의 [CI 실행](https://github.com/kswkm/TrustChain-AI/actions/runs/36807577616)에서 platform(`trustchain-platform`)·demo(`mnist-api`) 이미지 2종 모두
이미지 빌드 → cosign keyless 서명·SBOM/AI-BOM 증명 첨부 → SLSA L3 출처 증명 생성(detect-env · generator · final) 잡이 성공했습니다.
생성된 이미지를 Verify Gate(`trustchain verify <image@digest> --require-aibom`, cosign v2.4.1 · slsa-verifier v2.6.0 — CD 와 같은 버전)로
검증한 결과 두 이미지 모두 6개 항목(digest 지정 · cosign 서명 · 서명 클레임 · SLSA 출처 증명 · SBOM 증명 · AI-BOM 증명)을 통과했습니다.
Kyverno `trustchain-verify-images` 정책도 이 이미지(`ghcr.io/kswkm/mnist-api@sha256:972f1e92…`)의 Pod 생성을 허용했습니다 (5절).

## 5. 공급망 공격 시나리오 (목표 7종 전부 차단)

`python scenarios/run_all.py --offline --cluster --image <서명 없는 이미지@digest>` → **실행 7종 중 차단 7종**.

- 1~4번 : 로컬 재현.
- 5번 : `--vuln-image python:3.9-slim-buster@sha256:320a7a42…` 를 Trivy v0.75.0 으로 실제 스캔 → Debian 10.13(지원 종료) 에서 CRITICAL 2건
  (CVE-2019-8457, CVE-2023-45853, 모두 패치 없음) + 지원 종료 OS 규칙(TC-IMG-006) 으로 차단. 패치 없는 취약점은 기본 정책(`ignore_unfixed`)상
  차단 기준에서 빠지지만, 지원이 끝난 OS 는 앞으로도 패치가 나오지 않으므로 별도로 차단합니다. (실측 중 이 정책 공백을 발견해 보완)
  `--vuln-image` 없이 오프라인으로 실행하면 샘플 Trivy 리포트로 판정합니다.
- 6번 : CI 이미지에 레이어를 덧붙여 개발자 PC 에서 다시 빌드한 서명 없는 이미지(`ghcr.io/kswkm/mnist-api@sha256:bdd15eea…`)를 GHCR 에 직접 push →
  Verify Gate 가 cosign 서명·SLSA 출처 증명·SBOM·AI-BOM 증명 4개 항목 실패로 배포 차단 (종료 코드 1).
- 7번 : kind(Kubernetes v1.37) + Kyverno v1.19.1 클러스터에 `deploy/k8s` 의 네임스페이스·정책(CEL 기반 `ImageValidatingPolicy`·
  `ValidatingPolicy`)을 적용하고, PodSecurity restricted·워크로드 정책을 모두 지킨 Pod 를 서명 없는 이미지로 `kubectl apply` →
  `admission webhook "ivpol.validate.kyverno.svc-fail-finegrained-trustchain-verify-images" denied the request ... CI 워크플로우의 cosign 서명이 없습니다`.
  보안 설정을 모두 지킨 Pod 로 제출하므로 차단 원인은 서명·출처 정책뿐입니다 (2026-10-02 재실측, 5·6·7번을 한 번에 실행해 7종 모두 차단).
- 정책 범위 실측 (같은 클러스터, 서버 dry-run 8건 모두 기대대로) : CI 서명 이미지 Pod·Deployment 허용 / 서명 없는 이미지 Pod·Deployment,
  서명 이미지에 서명 없는 initContainer 를 섞은 Pod 는 `trustchain-verify-images` 가 거부 / digest 없는 태그 이미지, 메모리 limit 누락
  Pod·Deployment 는 `trustchain-workload-hardening` 이 거부. 두 정책 모두 Deployment·StatefulSet·DaemonSet·Job·CronJob 생성 시점에도
  적용되고(autogen), 이미지 정책은 일반·초기화·임시 컨테이너를 모두 검증합니다.
- 대조 : 같은 보안 설정의 Pod 명세에서 이미지만 CI 서명 이미지(`ghcr.io/kswkm/mnist-api@sha256:972f1e92…`)로 바꾸면 Kyverno 가 허용합니다.
  즉 차단 원인은 서명·증명 유무이며, 정책이 모든 이미지를 막는 것이 아닙니다.

- 실제 배포 (2026-10-03, kind + Calico v3.28.2 + Kyverno v1.19.1, [deploy/kind/verify.sh](../deploy/kind/verify.sh)) : CI 서명 이미지 Deployment 2/2 Ready,
  서명 없는 이미지 Deployment 거부(`trustchain-verify-images`), 태그 이미지 거부(`trustchain-workload-hardening`), 다른 네임스페이스 → 시연 서비스 HTTP 200,
  시연 서비스 → 외부 송신 차단(대조군은 연결 성공), trustchain 네임스페이스 PostgreSQL·수집 API·대시보드 Ready, 대시보드 → API → DB 조회 200,
  대시보드 → DB 직접 접속 차단 — 8건 모두 기대대로. 같은 스크립트를 CI `deploy-kind` 작업이 main push 마다 실행합니다 (첫 실행 : Actions run 37092451134, Verify Gate 통과 후 kind 검증 188초, 8건 통과).

절차는 [scenarios.md](scenarios.md) 에 있습니다. Verify Gate 의 판정 로직은
`tests/test_verify.py` 에서 서명 없음·저장소 불일치·출처 증명 없음·태그 참조를 각각 거부하는지 확인합니다.
