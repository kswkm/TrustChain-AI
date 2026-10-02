# TrustChain AI

**AI 기반 SW 공급망 신뢰 검증 및 시큐어코딩 지원 플랫폼** — 소프트웨어개발보안경진대회 트랙 B(기술혁신) · 팀 020

> 코드 한 줄부터 배포된 서비스까지, 신뢰할 수 있는 구성요소만 통과시킨다.

코드 작성부터 클라우드 배포까지 SW 구성요소의 출처·구성·위험도를 자동으로 검증하는 Python 기반 개발보안 플랫폼입니다.
시큐어코딩 점검, AI가 만든 가짜(환각)·유사명 패키지 탐지, SBOM·AI-BOM 생성, SLSA 출처 증명·서명 검증으로 신뢰할 수 없는
구성요소의 배포를 차단하고, RAG 기반 AI 보안 어시스턴트가 위험 우선순위와 한국어 조치 방법을 근거 문서와 함께 안내합니다.

## 기능 구성 (F1~F12)

| 단계 | 기능 | 구현 위치 |
|---|---|---|
| ① 개발 | **F1** 시큐어코딩 점검 (KISA 가이드 기준 자체 룰 16종 + Semgrep·Bandit 연동) | [src/trustchain/secure_coding](src/trustchain/secure_coding) |
| | **F2** 환각 패키지 탐지 (PyPI 존재·등록 시점, import ↔ 의존성 불일치) | [packages/checker.py](src/trustchain/packages/checker.py) |
| | **F3** 타이포스쿼팅 탐지 (편집거리·키보드 인접·형태 유사 문자·n-gram 임베딩 + 분류 모델) | [packages/typosquat.py](src/trustchain/packages/typosquat.py), [classifier.py](src/trustchain/packages/classifier.py) |
| | **F4** 의존성 신뢰 점수 0~100 (OSV·유지관리(PyPI 배포 + GitHub REST API 저장소 활동)·관리자 수·OpenSSF Scorecard) | [packages/trust_score.py](src/trustchain/packages/trust_score.py) |
| ② 빌드 | **F5** 보안 스캔 게이트 (코드·의존성(자체 OSV 조회 + 빌드 게이트에서 pip-audit·OSV-Scanner)·악성 pickle 모델·이미지(Trivy, 지원 종료 OS 차단)·IaC) | [scan/](src/trustchain/scan) |
| | **F6** SBOM(CycloneDX 1.6, Syft) + AI-BOM(모델·가중치 해시·데이터셋 출처) | [bom/](src/trustchain/bom) |
| | **F7** SLSA Build L3 출처 증명 · cosign keyless 서명 | [.github/workflows/trustchain-ci.yml](.github/workflows/trustchain-ci.yml) |
| ③ 배포 | **F8** Verify Gate (서명·인증서 클레임·SLSA·SBOM/AI-BOM 증명) | [attest/verify.py](src/trustchain/attest/verify.py), [trustchain-cd.yml](.github/workflows/trustchain-cd.yml) |
| | **F9** Kyverno 실행 정책 · IaC 점검 (자체 룰 + Checkov) | [deploy/k8s/kyverno](deploy/k8s/kyverno), [iac/k8s.py](src/trustchain/iac/k8s.py) |
| ④ 운영 | **F10** 취약점 피드 모니터 (OSV·NVD → SBOM 매칭 → Slack·메일) | [feed/](src/trustchain/feed) |
| | **F11** AI 보안 어시스턴트 (Kiwi + rank_bm25 키워드 검색 + 다국어 벡터 RRF 하이브리드 검색, Cross-encoder 리랭킹, 근거 인용, PR 초안) | [assistant/](src/trustchain/assistant) |
| | **F12** 대시보드 · 알림 (Streamlit) | [dashboard/app.py](src/trustchain/dashboard/app.py) |

## 심사용 3분 재현

Python 3.11 이상만 있으면 됩니다 (Docker·PostgreSQL 불필요).

```bash
# 설치 — Linux/macOS
python -m venv .venv && . .venv/bin/activate
# 설치 — Windows (PowerShell)
#   python -m venv .venv; .venv\Scripts\Activate.ps1
pip install -e ".[dev,server,dashboard]"

# ① 공급망 공격 시나리오 1~5 재현 → 어느 단계에서 차단되는지 표로 출력 (네트워크 불필요)
python scenarios/run_all.py --offline

# ② 수집 API + 시연 데이터 + 대시보드를 한 번에 실행 → http://localhost:8501 (Ctrl+C 로 종료)
python scripts/demo.py              # 네트워크가 없으면: python scripts/demo.py --offline
```

대시보드에서 확인할 것

| 탭 | 확인 포인트 |
|---|---|
| 서비스 신뢰 점수 | `legacy-api`(취약 버전 PyYAML·requests 고정, 하드코드 토큰)의 낮은 점수와 감점 내역, 발견 항목의 KISA 가이드 매핑 |
| 취약점 알림 | SBOM 수집 즉시 OSV 와 매칭된 `legacy-api` 취약점 알림 (네트워크 필요) |
| 차단 이력 | `attack-scenarios` : 시나리오 1~5 가 커밋·빌드 단계에서 차단된 근거 |
| AI 보안 어시스턴트 | 서비스 맥락 `legacy-api` 선택 후 "가장 먼저 고쳐야 할 취약점은?" — 근거 문서 인용과 함께 답변 (`ANTHROPIC_API_KEY` 가 있으면 Claude 가 답변을 작성, 없으면 근거 문장 발췌) |

## 빠른 시작

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"            # 서버: .[server]  AI 모델: .[ai]  대시보드: .[dashboard]  TensorFlow: .[ml]

# ① 커밋 전 점검 (시큐어코딩 + 패키지 판정)
trustchain check                      # 프로젝트 전체
trustchain check --staged             # git 스테이징 파일만 (pre-commit)

# AI 가 추천한 패키지를 설치 전에 판정
trustchain pkg reqeusts colourama requests==2.31.0

# ② 빌드 게이트 · SBOM · AI-BOM
trustchain gate --format json -o reports/gate.json --sarif reports/gate.sarif
trustchain sbom --with-aibom -o sbom.cdx.json
trustchain aibom -o aibom.cdx.json && trustchain aibom-verify aibom.cdx.json
trustchain scan-model ./models

# ③ 배포 전 검증
trustchain verify ghcr.io/org/app@sha256:<digest> --repo github.com/org/app \
  --workflow .github/workflows/trustchain-ci.yml --signer-repo github.com/kswkm/TrustChain-AI

# ④ 운영 : 수집 API · 피드 모니터 · AI 어시스턴트
trustchain token --name ci --role ingest
trustchain server --port 8000
trustchain feed
trustchain ask "우리 서비스에서 가장 먼저 고쳐야 할 취약점은?" --report reports/gate.json --root .
trustchain pr-draft --report reports/gate.json --requirements requirements.txt
```

### pre-commit

```yaml
repos:
  - repo: https://github.com/kswkm/TrustChain-AI
    rev: <commit-sha>
    hooks:
      - id: trustchain-check
```

### GitHub Actions (다른 저장소에서 설정 몇 줄로 적용)

```yaml
jobs:
  trustchain:
    uses: kswkm/TrustChain-AI/.github/workflows/trustchain-ci.yml@<commit-sha>
    with: { context: ".", service: "my-api" }
    permissions: { contents: read, packages: write, id-token: write, actions: read, security-events: write }
    secrets: { trustchain-token: "${{ secrets.TRUSTCHAIN_TOKEN }}" }
```

### 로컬 플랫폼 실행

빠르게 확인하려면 `python scripts/demo.py` (SQLite, 위 [심사용 3분 재현](#심사용-3분-재현) 참고).
운영형 구성은 `docker compose up -d --build` (PostgreSQL+pgvector · 수집 API · 대시보드) — 절차는 [docker-compose.yml](docker-compose.yml) 상단 주석 참고.
Kubernetes 배포는 `kubectl apply -k deploy/k8s` ([deploy/k8s](deploy/k8s)).

## 검증 결과 (현재 저장소 기준, 재현 명령 포함)

| 지표 | 목표 | 결과 | 재현 |
|---|---|---|---|
| 공급망 공격 시나리오 차단 | 7종 전부 | **7종 모두 차단** (5번 실제 Trivy 스캔, 6번 GHCR 실제 레지스트리, 7번 kind + Kyverno 클러스터 실측) | `python scenarios/run_all.py --offline` (5번 : `--vuln-image <이미지>`, 6·7번 : `--cluster --image <서명 없는 이미지@digest>`) |
| 타이포스쿼팅·환각 탐지 F1 | 0.9 이상 | TensorFlow(Keras) 분류 모델 위험 탐지 F1 **0.999**, 3-클래스 macro F1 **0.991** (자체 구축 합성 평가셋, 576건) | `trustchain model eval --out src/trustchain/data/package_model.keras` (TensorFlow 필요) |
| SBOM 매칭 후 알림 | 1분 이내 | SBOM 수집 → OSV 매칭 → 알림까지 테스트에서 60초 미만을 확인 | `pytest tests/test_server_feed.py` |
| 빌드 신뢰 수준 | SLSA Build L3 | slsa-github-generator 컨테이너 생성기로 **GitHub Actions 에서 출처 증명 생성 성공** (platform·demo 이미지 2종, [CI 실행 기록](https://github.com/kswkm/TrustChain-AI/actions/runs/36807577616)), 생성된 이미지 2종 모두 **Verify Gate 검증 통과** (cosign 서명·서명 클레임·slsa-verifier·SBOM·AI-BOM 증명) | `.github/workflows/trustchain-ci.yml` |
| AI 어시스턴트 검색 Recall@5 | 0.8 이상 | 실제 다국어 임베딩·Cross-encoder 로 운영 규모 지식베이스(57,337 청크)에서 하이브리드 **0.969** (MRR 0.893), 내장 지식베이스 1.00. 리랭킹은 내장에서 MRR 개선(0.945→0.953), 운영 규모에서는 하락(0.893→0.870) | `trustchain eval --answers --osv-dir <OSV 덤프>` |

- 분류 모델 평가셋은 인기 패키지 이름에 공개 보고된 위장 패턴을 적용하고 메타데이터를 전형적 분포에서 표본 추출해 만든 **합성 데이터**입니다.
  실제 PyPI 데이터(OSV 악성 11,768건 · 정상 2,000개) 검증에서는 정상 패키지 실사용 오탐률 7.8%(차단 2.1%, Keras),
  메타데이터 없는 이름 신호의 typosquat 탐지는 AUC 0.563 · 오탐률 1% 에서 12.9% 로 제한적이었습니다 ([docs/evaluation.md](docs/evaluation.md) 1절).
- 패키지 판정 모델 : TensorFlow 가 설치된 환경(CI 게이트, `.[ml]`)은 TensorFlow(Keras) 모델로, 설치되지 않은 환경(가벼운 pre-commit)은
  같은 평가셋에서 위험 탐지 F1 0.995 · macro F1 0.950 인 경량 선형 모델로 판정합니다. CI 게이트는 `TRUSTCHAIN_PKG_MODEL=keras` 로 Keras 판정을 강제하며,
  판정 결과에는 판정 주체(분류 모델 이름, 또는 PyPI 에 없는 패키지처럼 모델 이전에 결론 난 경우 "규칙 (...)")가 표시됩니다.
- RAG 수치는 실제 모델(multilingual-e5-small, mmarco Cross-encoder, Kiwi + rank_bm25)과 외부 모델 없는 기준선을 모두 측정했습니다. 측정 조건·지식베이스 구성은 [docs/evaluation.md](docs/evaluation.md) 2절에 있습니다.

상세 설명: [docs/architecture.md](docs/architecture.md) · [docs/scenarios.md](docs/scenarios.md) · [docs/evaluation.md](docs/evaluation.md)

## 플랫폼 자체 개발보안

| 유형 | 적용 |
|---|---|
| 입력데이터 검증 | 모든 API 요청은 pydantic 스키마로 검증(`extra="forbid"`, 길이·패턴·범위 제한), 요청 본문 크기 제한, 검증 오류 응답에 입력값을 되돌려주지 않음. SBOM 파일 업로드(`/api/v1/sboms/upload`)는 `.json` 만·기본 10MB 제한, 파일명은 경로 구분자 제거·허용 문자 정규화, 서버 경로에 저장하지 않고(1MB 초과분은 요청 동안만 임시 파일) CycloneDX 검증 |
| SQL 삽입 | SQLAlchemy ORM·바인딩 파라미터만 사용 (pgvector 질의 벡터도 바인딩) |
| 인증·권한 | API 토큰은 SHA-256 해시로만 저장, reader/ingest/admin 역할별 최소 권한, Actions 잡마다 `permissions` 명시 |
| 중요정보 노출 | 비밀정보는 Secret/OIDC 로만 주입, 로그 마스킹 필터, 500 오류에는 요청 ID 만 반환 |
| 역직렬화 | pickle 미사용 (모델 가중치·HTTP 캐시 모두 JSON / `.keras` safe_mode + 해시 검증) |
| LLM 위협 | 검색 문서는 데이터 블록으로만 전달하고 태그 위장 문자열을 무력화, 인용 번호 검증, 코드 자동 실행 없음 |
| 공급망 | 의존성 해시 고정(`requirements.lock`, `pip install --require-hashes`, 플랫폼·데모 이미지), 서드파티 Actions 커밋 SHA 고정, CI 도구 버전·바이너리 SHA-256 고정, 베이스 이미지 digest 고정, RAG 임베딩·리랭킹 모델은 HuggingFace 커밋 리비전으로 고정, 플랫폼 이미지에도 SBOM·AI-BOM(분류 모델·RAG 모델 4종, `models.toml`)·서명·출처 증명 적용, CI 에서 자체 점검(dogfooding) |

## 개발

```bash
pytest -q          # 단위·통합 테스트 (네트워크 없이 실행)
ruff check src tests
```

라이선스: Apache-2.0
