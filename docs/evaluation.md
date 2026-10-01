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

**한계** : 메타데이터 분포를 가정해 만든 데이터이므로 실제 PyPI 에서의 성능을 보장하지 않습니다. 실측 검증에는 PyPI 에서 삭제된
악성 패키지 보고 목록과 정상 패키지를 라벨링한 데이터가 필요합니다. 환각 패키지(PyPI 에 존재하지 않음)는 모델이 아니라 규칙으로 판정하므로
PyPI 조회가 성공하면 탐지 누락이 없습니다.

## 2. AI 어시스턴트 검색 정확도 (목표 Recall@5 ≥ 0.8, 리랭킹 전후 비교)

```bash
trustchain eval --offline-models --answers      # 외부 모델 없는 기준선
pip install .[ai] && trustchain eval --answers  # multilingual-e5-small + Cross-encoder + Kiwi
```

평가셋 `eval/rag_eval.jsonl` : 32문항 (KISA 시큐어코딩 요약 19, 공급망 7, OSV 권고문 6). 지식베이스 76개 청크.

| 단계 | Recall@5 | Hit@5 | MRR |
|---|---|---|---|
| BM25 | 0.969 | 0.969 | 0.862 |
| 벡터 | 0.969 | 0.969 | 0.823 |
| 하이브리드 (RRF) | 1.000 | 1.000 | 0.896 |
| **하이브리드 + 리랭킹** | **1.000** | **1.000** | **0.912** |

측정 조건 : 해싱 임베딩(문자 n-gram, 384차원) · 정규식 토크나이저 · 어휘 리랭커. 답변 충실도(faithfulness)는 LLM 없이 문장을 발췌하는
기준선에서 1.0 으로, 발췌 방식이라 당연히 높게 나옵니다. LLM 을 연결하면(`TRUSTCHAIN_LLM_API_KEY`) 같은 지표로 생성형 답변을 평가합니다.
지식베이스·평가셋이 작아 수치가 높게 나오므로, 지식베이스를 OSV 전체 덤프(`trustchain kb --osv-dir`)로 늘린 뒤 다시 측정해야 합니다.

## 3. 신규 취약점 영향 서비스 식별 (목표 SBOM 매칭 후 1분 이내 알림)

`tests/test_server_feed.py::test_ingest_flow_trust_score_and_alert_latency` : SBOM 수집 → OSV 매칭 → Alert 생성 → 알림 전송까지를 한 요청 안에서
처리하고 60초 미만을 확인합니다 (가짜 OSV 응답 사용). 피드 모니터는 알림마다 `matched_at`/`notified_at` 과 지연 시간(ms)을 기록합니다.
주기 수집 간격은 `TRUSTCHAIN_FEED_INTERVAL_MIN`(기본 10분)이며, "발표 → 수집" 지연은 이 간격에 좌우됩니다.

## 4. 빌드 신뢰 수준 (목표 SLSA Build L3)

`trustchain-ci.yml` 이 `slsa-framework/slsa-github-generator` 의 `generator_container_slsa3.yml@v2.1.0` 을 호출해 출처 증명을 생성합니다.
Verify Gate 와 Kyverno 정책은 이 빌더 ID 로 만들어진 증명만 허용합니다.

**실행 결과** : 커밋 `c271b15` 의 [CI 실행](https://github.com/kswkm/TrustChain-AI/actions/runs/36807577616)에서 platform(`trustchain-platform`)·demo(`mnist-api`) 이미지 2종 모두
이미지 빌드 → cosign keyless 서명·SBOM/AI-BOM 증명 첨부 → SLSA L3 출처 증명 생성(detect-env · generator · final) 잡이 성공했습니다.
생성된 증명을 Verify Gate(`trustchain-cd.yml`)·Kyverno 로 검증하는 실측은 아직 하지 않았습니다.

## 5. 공급망 공격 시나리오 (목표 7종 전부 차단)

`python scenarios/run_all.py --offline` → 로컬에서 재현할 수 있는 1~5번 **5종 모두 차단**. 6(서명 없는 이미지)·7(kubectl 우회)은
레지스트리·Kyverno 클러스터에서 실행해야 하며 절차는 [scenarios.md](scenarios.md) 에 있습니다. Verify Gate 의 판정 로직은
`tests/test_verify.py` 에서 서명 없음·저장소 불일치·출처 증명 없음·태그 참조를 각각 거부하는지 확인합니다.
