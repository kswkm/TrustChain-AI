# SW 공급망 보안 조치 가이드

> TrustChain AI 팀이 작성한 공급망 위협 유형별 조치 안내입니다.

## 패키지 환각 (Slopsquatting, CWE-1357)
AI 코딩 도구가 실제로 존재하지 않는 패키지 이름을 제안하는 현상을 패키지 환각이라고 합니다. 공격자는 자주 환각되는 이름을 PyPI·npm 에 미리 등록해 두고, 개발자가 제안을 그대로 pip install 하면 악성 코드가 실행되게 만듭니다.
조치 방법: AI 가 제안한 패키지는 설치 전에 PyPI 존재 여부, 최초 등록일, 다운로드·저장소 정보를 확인합니다. TrustChain CLI 는 requirements.txt 와 import 구문을 분석해 존재하지 않는 패키지를 차단으로 판정하고 커밋을 막습니다.
TrustChain 룰: TC-PKG-001.

## 타이포스쿼팅 (Typosquatting)
유명 패키지와 한두 글자 다른 이름(키보드 인접 문자 치환, 0/o·l/1/I 치환, 구분자 변경, python- 접두사 추가, 문자 누락·중복·자리바꿈)으로 악성 패키지를 등록해 오타를 노리는 공격입니다. 이런 패키지는 대개 최근 등록되었고 배포 이력과 설명이 적으며 소스 저장소가 없고 설치 스크립트(setup.py)로 코드를 실행합니다.
조치 방법: 의존성 이름을 공식 문서와 대조하고, 버전과 해시를 고정합니다. TrustChain 은 인기 패키지와의 편집거리·문자 치환 패턴·이름 임베딩 유사도와 메타데이터 특징을 결합한 분류 모델로 정상/주의/차단을 판정합니다.
TrustChain 룰: TC-PKG-002, TC-PKG-005.

## 의존성 신뢰 점수
알려진 취약점(OSV), 최근 배포 시점과 배포 이력(유지관리 활동), 관리자 수, OpenSSF Scorecard 점수를 종합해 0~100점으로 계산합니다. 점수가 낮은 패키지는 유지관리가 중단되었거나 단일 관리자에 의존해 계정 탈취 시 위험이 큽니다.
조치 방법: 신뢰 점수 기준(min_trust_score)을 정책으로 설정하고, 낮은 점수의 패키지는 활발히 관리되는 대체 패키지로 교체합니다.

## 악성 AI 모델 파일
pickle 기반 모델(.pkl, .pt, .pth, .bin, .joblib)은 로드 시 GLOBAL/STACK_GLOBAL opcode 로 가져온 os.system, subprocess, builtins.exec 같은 함수를 REDUCE 로 실행할 수 있습니다. 공개 모델 허브에 이런 모델이 업로드된 사례가 보고되었습니다.
조치 방법: 모델을 불러오기 전에 opcode 를 정적으로 스캔하고, safetensors 나 Keras .keras(safe_mode) 형식을 사용합니다. AI-BOM 에 모델 이름·버전·가중치 SHA-256·원본 저장소와 리비전·학습 데이터 출처를 기록하고 배포·실행 시 해시를 대조합니다.
TrustChain 룰: TC-MODEL-001(위험 호출 포함, CRITICAL), TC-MODEL-003(허용 목록에 없는 전역 참조).

## SBOM 과 AI-BOM
SBOM(Software Bill of Materials)은 소프트웨어에 포함된 모든 구성요소(직접·간접 의존성, OS 패키지)의 이름·버전·식별자(purl)를 기록한 명세입니다. 새 취약점이 발표되면 SBOM 을 검색해 영향받는 서비스를 즉시 찾을 수 있습니다. AI-BOM 은 CycloneDX 의 machine-learning-model·data 구성요소로 AI 모델과 데이터셋 출처를 기록합니다.
조치 방법: 빌드마다 Syft 로 CycloneDX SBOM 을 생성하고, cosign attest 로 이미지에 서명된 증명으로 첨부합니다. TrustChain 피드 모니터는 OSV·NVD 신규 취약점을 저장된 SBOM 과 매칭해 Slack·메일로 알립니다.

## SLSA 출처 증명과 keyless 서명
SLSA(Supply-chain Levels for Software Artifacts) Build Level 3 은 격리된 호스팅 빌드 플랫폼이 위조할 수 없는 출처 증명(Provenance)을 생성하는 수준입니다. 출처 증명에는 빌드한 저장소, 커밋, 워크플로우, 빌더 ID 가 기록됩니다. Sigstore cosign keyless 서명은 GitHub Actions OIDC 토큰으로 Fulcio 에서 단기 인증서를 받아 서명하고 Rekor 투명성 로그에 기록하므로 장기 서명 키를 관리할 필요가 없습니다.
조치 방법: slsa-github-generator 의 generator_container_slsa3 워크플로우로 출처 증명을 생성하고, 배포 전 cosign verify(서명 주체·OIDC 발급자 확인)와 slsa-verifier verify-image(소스 저장소·브랜치·빌더 확인)를 통과한 digest 만 배포합니다. 클러스터에서는 Kyverno verifyImages 정책으로 서명·출처 증명이 없는 이미지의 Pod 생성을 거부합니다.

## 빌드 파이프라인 공격 (SolarWinds, xz Utils)
SolarWinds 사건(2020)은 빌드 과정에서 악성 코드가 삽입되어 정상 서명된 업데이트로 배포되었습니다. xz Utils 백도어(CVE-2024-3094)는 장기간 신뢰를 쌓은 관리자가 배포 tarball 과 테스트 파일에 백도어를 숨긴 사례입니다. 두 사례 모두 소스 코드 리뷰만으로는 탐지하기 어렵습니다.
조치 방법: 빌드는 격리된 호스팅 러너에서 수행하고 출처 증명으로 결과물과 소스·워크플로우의 연결을 증명합니다. 서드파티 Actions 와 베이스 이미지는 커밋 SHA·digest 로 고정하고, 워크플로우 권한(permissions)을 최소화합니다.
