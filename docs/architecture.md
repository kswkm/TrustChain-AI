# 시스템 아키텍처

개발기획서 2-3 의 네 영역(개발자 PC · GitHub · 클라우드 · 외부 서비스)과 구현 모듈의 대응 관계입니다.

```
개발자 PC                         GitHub                                   클라우드 (Kubernetes)
┌──────────────┐  commit  ┌───────────────────────────────┐        ┌──────────────────────────────────┐
│ IDE·AI 코딩  │────────▶│ trustchain-ci.yml (재사용)     │        │ Kyverno (ImageValidatingPolicy)   │
│ trustchain   │          │  ① gate: 코드·의존성·모델·IaC │        │  서명·SLSA·SBOM 증명 없으면 거부   │
│  check (F1~4)│  push    │  ② build → GHCR (digest)       │ deploy │        │                          │
│ pre-commit   │────────▶│  ③ Trivy 이미지 게이트         │───────▶│ app ns: mnist-api (digest 고정)   │
└──────┬───────┘          │  ④ Syft SBOM + AI-BOM          │        │                                   │
       │ PyPI·OSV·        │  ⑤ cosign sign/attest (OIDC)   │        │ trustchain ns:                    │
       │ Scorecard API    │  ⑥ SLSA L3 provenance          │        │  수집 API(FastAPI) ─ PostgreSQL   │
       ▼                  │ trustchain-cd.yml              │        │  피드 모니터(CronJob)  + pgvector │
  외부 서비스              │  Verify Gate(F8) → kubectl     │        │  대시보드(Streamlit)              │
  OSV · NVD · PyPI ·      └───────────────────────────────┘        └──────────────────────────────────┘
  Sigstore(Fulcio·Rekor) · Slack · LLM API
```

## 모듈 구성

| 경로 | 역할 |
|---|---|
| `core/` | Finding·Report(SARIF), 설정(TOML), 마스킹 로거, 캐시·크기 제한 HTTP 클라이언트 |
| `secure_coding/` | AST 기반 경량 오염 분석 룰(16종), Semgrep 룰(`semgrep_kisa.yml`), Bandit 결과 매핑 |
| `packages/` | requirements/pyproject 파서, import 분석, PyPI·OSV·Scorecard·GitHub REST API 클라이언트, 타이포스쿼팅 특징, 분류 모델, 신뢰 점수, 통합 판정기, 실측 평가 |
| `scan/` | 모델 파일 정적 스캐너(pickle opcode, zip/PyTorch, Keras Lambda, npy, safetensors), Dockerfile·Trivy(지원 종료 OS 차단), pip-audit·OSV-Scanner 연동(자체 OSV 결과와 별칭 기준 중복 제거), 게이트 |
| `bom/` | CycloneDX 1.6 SBOM (Syft 또는 자체 생성), AI-BOM (machine-learning-model·data), 해시 대조 |
| `attest/` | Verify Gate (cosign·slsa-verifier 실행, 인증서 클레임·in-toto statement 검증) |
| `iac/` | Kubernetes 매니페스트 보안 룰, Checkov 연동 |
| `server/` | SQLAlchemy 모델, 토큰 인증, pydantic 스키마, 수집 API, SBOM 파일 업로드(형식·크기 제한, 파일명 정규화) |
| `feed/` | OSV modified_id.csv 증분 수집, NVD 보강, SBOM 매칭, Slack·메일 알림 |
| `assistant/` | 청킹, Kiwi/정규식 토크나이저, BM25, 임베딩, RRF, 리랭커, LLM, 프롬프트 분리, 우선순위, PR 초안, 평가 |
| `dashboard/` | Streamlit 대시보드 (수집 API 만 호출, reader 토큰) |

## 판정 흐름

### F2·F3 패키지 판정
1. 허용 목록 → 정상
2. URL/VCS 직접 참조 → 커밋 해시 고정 여부로 주의
3. PyPI 조회 : 존재하지 않음 → **차단 (환각)** / 조회 실패 → 주의
4. import 이름으로 선언(`sklearn`, `cv2`…) → 주의
5. 이름 특징 6개 + 메타데이터 특징 6개 → 분류 모델 (정상/주의/차단) + 판정 근거(특징 기여도)
6. 규칙 보정 : 등록 7일 미만 → 최소 주의, 등록 7일 미만 + 인기 패키지와 편집거리 2 이하 → 차단, 대문자 I 로 l 위장 → 차단
7. OSV 취약점 + 유지관리(PyPI 배포·GitHub 저장소 활동) + Scorecard → 신뢰 점수, 정책 하한 미달 시 주의

### F5 게이트 정책
빌드 게이트(`trustchain gate`)는 `trustchain.toml` 의 `[gate]` (기본: CRITICAL 1건 이상 실패, 차단 패키지 1건 이상 실패),
커밋 시점 점검(`trustchain check` · pre-commit/pre-push)은 `[check]` 의 심각도 한도·분류만 덮어씁니다 (기본: 코드·패키지 판정에서
HIGH 이상 1건 이상 실패, 의존성 권고문은 보고만 하고 빌드 게이트가 판정, 신뢰 점수 하한 등 나머지는 `[gate]` 를 따름).
외부 도구(pip-audit·OSV-Scanner·ModelScan·Checkov)의 실행 상태(ok/missing/failed/offline)는 리포트 `meta` 에 남습니다. 결과는 JSON·SARIF 로 출력하고
GitHub Code Scanning 에 업로드합니다.

### F8 Verify Gate
digest 형식 → `cosign verify`(SAN 정규식 = 서명 재사용 워크플로우, 발급자 = GitHub OIDC) → 인증서의 저장소·브랜치 클레임 →
`slsa-verifier verify-image`(빌더 ID·소스 저장소·브랜치) → `cosign verify-attestation --type cyclonedx` → (선택) AI-BOM 증명.

### F11 RAG
수집·청킹(문서 구조 단위) → 임베딩(multilingual-e5-small, 없으면 해싱) → BM25(Kiwi) + 벡터 → RRF(k=60) → 리랭킹(Cross-encoder, 없으면 어휘 리랭커)
→ 시스템 프롬프트(근거 문서 안에서만 답변·인용·모르면 모른다고 답변) → 출력 검증(인용 범위) → 답변·근거·우선순위.

## 데이터 모델

`services` · `artifacts`(digest, signed, provenance) · `components`(SBOM 인벤토리, ecosystem+name 인덱스) · `scan_reports` ·
`gate_events`(차단 이력) · `vulnerabilities` · `alerts`(matched_at/notified_at) · `api_tokens`(해시) · `knowledge_chunks`(pgvector) · `feed_state`
