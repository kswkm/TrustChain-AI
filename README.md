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
| | **F4** 의존성 신뢰 점수 0~100 (OSV·유지관리·관리자 수·OpenSSF Scorecard) | [packages/trust_score.py](src/trustchain/packages/trust_score.py) |
| ② 빌드 | **F5** 보안 스캔 게이트 (코드·의존성·악성 pickle 모델·이미지·IaC) | [scan/](src/trustchain/scan) |
| | **F6** SBOM(CycloneDX 1.6, Syft) + AI-BOM(모델·가중치 해시·데이터셋 출처) | [bom/](src/trustchain/bom) |
| | **F7** SLSA Build L3 출처 증명 · cosign keyless 서명 | [.github/workflows/trustchain-ci.yml](.github/workflows/trustchain-ci.yml) |
| ③ 배포 | **F8** Verify Gate (서명·인증서 클레임·SLSA·SBOM/AI-BOM 증명) | [attest/verify.py](src/trustchain/attest/verify.py), [trustchain-cd.yml](.github/workflows/trustchain-cd.yml) |
| | **F9** Kyverno 실행 정책 · IaC 점검 (자체 룰 + Checkov) | [deploy/k8s/kyverno](deploy/k8s/kyverno), [iac/k8s.py](src/trustchain/iac/k8s.py) |
| ④ 운영 | **F10** 취약점 피드 모니터 (OSV·NVD → SBOM 매칭 → Slack·메일) | [feed/](src/trustchain/feed) |
| | **F11** AI 보안 어시스턴트 (Kiwi BM25 + 벡터 RRF 하이브리드 검색, 리랭킹, 근거 인용, PR 초안) | [assistant/](src/trustchain/assistant) |
| | **F12** 대시보드 · 알림 (Streamlit) | [dashboard/app.py](src/trustchain/dashboard/app.py) |

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

`docker compose up -d --build` (PostgreSQL+pgvector · 수집 API · 대시보드) — 절차는 [docker-compose.yml](docker-compose.yml) 상단 주석 참고.
Kubernetes 배포는 `kubectl apply -k deploy/k8s` ([deploy/k8s](deploy/k8s)).

## 검증 결과 (현재 저장소 기준, 재현 명령 포함)

| 지표 | 목표 | 결과 | 재현 |
|---|---|---|---|
| 공급망 공격 시나리오 차단 | 7종 전부 | **로컬 재현 5종 모두 차단**. 6·7번은 레지스트리·클러스터가 필요해 아직 실측하지 않음 | `python scenarios/run_all.py --offline` |
| 타이포스쿼팅·환각 탐지 F1 | 0.9 이상 | 위험 탐지 F1 **0.995**, 3-클래스 macro F1 **0.950** (자체 구축 합성 평가셋, 576건) | `trustchain model eval` |
| SBOM 매칭 후 알림 | 1분 이내 | SBOM 수집 → OSV 매칭 → 알림까지 테스트에서 60초 미만을 확인 | `pytest tests/test_server_feed.py` |
| 빌드 신뢰 수준 | SLSA Build L3 | slsa-github-generator 컨테이너 생성기 연동 워크플로우 작성. GitHub 에서는 아직 실행하지 않음 | `.github/workflows/trustchain-ci.yml` |
| AI 어시스턴트 검색 Recall@5 | 0.8 이상 | 하이브리드+리랭킹 **1.00**, MRR 0.862(BM25) → 0.896(RRF) → **0.912**(리랭킹) | `trustchain eval --offline-models` |

- 분류 모델 평가셋은 인기 패키지 이름에 공개 보고된 위장 패턴을 적용하고 메타데이터를 전형적 분포에서 표본 추출해 만든 **합성 데이터**입니다.
  실제 PyPI 분포에서의 성능은 실측 라벨 데이터로 따로 확인해야 합니다.
- RAG 수치는 외부 모델 없이 측정한 기준선(해싱 임베딩, 어휘 리랭커, 평가셋 32문항)입니다. 다국어 임베딩 모델과 Cross-encoder 를 설치하면(`.[ai]`)
  같은 명령으로 다시 측정할 수 있습니다.

상세 설명: [docs/architecture.md](docs/architecture.md) · [docs/scenarios.md](docs/scenarios.md) · [docs/evaluation.md](docs/evaluation.md)

## 플랫폼 자체 개발보안

| 유형 | 적용 |
|---|---|
| 입력데이터 검증 | 모든 API 요청은 pydantic 스키마로 검증(`extra="forbid"`, 길이·패턴·범위 제한), 요청 본문 크기 제한, 검증 오류 응답에 입력값을 되돌려주지 않음 |
| SQL 삽입 | SQLAlchemy ORM·바인딩 파라미터만 사용 (pgvector 질의 벡터도 바인딩) |
| 인증·권한 | API 토큰은 SHA-256 해시로만 저장, reader/ingest/admin 역할별 최소 권한, Actions 잡마다 `permissions` 명시 |
| 중요정보 노출 | 비밀정보는 Secret/OIDC 로만 주입, 로그 마스킹 필터, 500 오류에는 요청 ID 만 반환 |
| 역직렬화 | pickle 미사용 (모델 가중치·HTTP 캐시 모두 JSON / `.keras` safe_mode + 해시 검증) |
| LLM 위협 | 검색 문서는 데이터 블록으로만 전달하고 태그 위장 문자열을 무력화, 인용 번호 검증, 코드 자동 실행 없음 |
| 공급망 | 서드파티 Actions 커밋 SHA 고정, 베이스 이미지 digest 고정, 플랫폼 이미지에도 SBOM·서명·출처 증명 적용, CI 에서 자체 점검(dogfooding) |

## 개발

```bash
pytest -q          # 단위·통합 테스트 (네트워크 없이 실행)
ruff check src tests
```

라이선스: Apache-2.0
