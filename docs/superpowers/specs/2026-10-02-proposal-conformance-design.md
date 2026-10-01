# 개발기획서 대비 구현 정합성 보완 설계

- 작성일 : 2026-10-02
- 상태 : 사용자 지시("개발기획서에 맞춰 모든 걸 완성")에 따라 자율 결정, 구현 진행

## 1. 배경

개발기획서(`020_개발기획서.pdf`)는 서류심사의 기준이며 허위 기재가 없어야 한다. 기획서의 기능(F1~F12)·핵심 기술(2-5)·
자체 시큐어코딩(2-6)·개발환경(2-7)·정량 목표(3-4)·시나리오(3-5)를 코드와 대조한 결과 아래 불일치가 있었다.

| # | 기획서 | 실제 | 조치 |
|---|---|---|---|
| G1 | 2-7 `rank_bm25 + Kiwi` | 자체 BM25 구현 | `rank_bm25.BM25Okapi` 사용 (server·ai·dev extra), 미설치 환경만 자체 구현 대체 |
| G2 | 2-7 `pip-audit` 연동 | 미사용 | F5 게이트에 pip-audit 연동 (설치 시 실행, JSON → Finding) |
| G3 | 2-7 `OSV-Scanner` 연동 | 미사용 | F5 게이트에 osv-scanner 연동 (설치 시 실행, JSON → Finding) |
| G4 | 2-7 `GitHub REST API` | 미사용 | F4 신뢰 점수의 유지관리 활동에 GitHub 저장소 정보(archived·최근 push) 반영 |
| G5 | 2-6 "업로드 파일은 형식·크기 제한과 경로 조작 방지(파일명 정규화)" | 파일 업로드 경로 없음 | 수집 API 에 SBOM 파일 업로드(multipart) + 대시보드 업로드 화면 |
| G6 | 2-6 "의존성 해시 고정" | 이미지 빌드가 해시 고정 없이 설치 (데모는 lock 이 있으면 쓰도록만 되어 있음) | 플랫폼·데모 이미지용 해시 고정 lock 생성·커밋, Dockerfile 에서 `--require-hashes` |
| G7 | 2-5(1) 다국어 임베딩·Cross-encoder, 3-4 리랭킹 전후 개선 | 외부 모델 없는 기준선만 측정 | `.[ai]` 실제 모델로 측정해 문서화 |
| G8 | 3-5 취약 OS 패키지 베이스 이미지 (F5) | 샘플 Trivy 리포트로만 판정 | 실제 Trivy 로 오래된 베이스 이미지를 스캔해 실측 |
| G9 | 2-5(1) OSV·NVD 권고문 수집 | 지식베이스 76청크(권고문 10건) | OSV PyPI 덤프로 지식베이스 확대 후 RAG 재측정 |

## 2. 결정

- 외부 도구(pip-audit·osv-scanner·trivy)는 기존 Semgrep·Bandit·Checkov 연동과 같은 방식 : `shutil.which` 로 있으면 실행, 없으면 건너뜀
  (Finding 없음, 게이트 리포트에 "미설치로 건너뜀" 정보). CI 게이트에는 설치한다 (버전·해시 고정).
- 중복 : pip-audit·osv-scanner 결과와 자체 OSV 조회(F2·F4)가 같은 취약점을 내면 (패키지, 버전, 취약점 ID) 기준으로 하나만 남긴다.
- GitHub REST API 는 토큰 없이도 동작(비인증 한도 60회/시간), `GITHUB_TOKEN` 이 있으면 사용. 실패 시 점수에서 해당 항목만 제외.
- 업로드 : `.json` 만, 기본 10MB, 파일명은 `os.path.basename` + 허용 문자 정규화 후 저장하지 않고 메모리에서 CycloneDX 검증 → 기존 SBOM 수집 경로.
- lock : `python:3.11-slim`(Debian 기반 리눅스) 컨테이너에서 `pip-compile --generate-hashes` 로 생성.
- 측정 수치는 낮게 나와도 그대로 보고한다.
