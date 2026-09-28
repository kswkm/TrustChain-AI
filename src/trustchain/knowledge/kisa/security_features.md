# KISA 시큐어코딩 가이드(Python) 요약 - 보안기능

> TrustChain AI 팀이 KISA 「Python 시큐어코딩 가이드」 보안기능 항목을 참고해 작성한 요약입니다.

## 하드코드된 중요정보 (CWE-798)
비밀번호, API 키, 토큰, 개인키를 소스 코드나 설정 파일에 직접 적으면 저장소를 열람할 수 있는 누구나 사용할 수 있고 Git 이력에도 남습니다.
조치 방법: 환경변수(os.environ["DB_PASSWORD"]), 비밀 저장소(GitHub Secrets, Kubernetes Secret, Vault)에서 읽습니다. 클라우드 인증은 장기 키 대신 OIDC 기반 임시 자격증명을 사용합니다. 이미 커밋된 토큰은 즉시 폐기(revoke)·재발급하고 git filter-repo 등으로 이력에서 제거합니다.
TrustChain 룰: TC-SECRET-001(변수 하드코딩), TC-SECRET-002(AWS·GitHub·Slack 토큰, 개인키 패턴).

## 신뢰할 수 없는 데이터의 역직렬화 (CWE-502)
pickle, dill, joblib, shelve, marshal 은 로드하는 순간 __reduce__ 로 지정된 임의 함수가 실행됩니다. yaml.load 에 SafeLoader 를 지정하지 않거나 torch.load 를 weights_only=True 없이 호출해도 같은 위험이 있습니다.
조치 방법: 외부 데이터는 JSON 으로 교환하고, YAML 은 yaml.safe_load 를 사용합니다. AI 모델은 safetensors 또는 Keras .keras 형식을 safe_mode=True 로 로드하며, 로드 전에 AI-BOM 에 기록된 SHA-256 해시와 비교합니다. torch.load 는 weights_only=True 를 지정합니다.
TrustChain 룰: TC-DESER-001, 모델 파일 스캔 TC-MODEL-001~004.

## 취약한 암호화 알고리즘 사용 (CWE-327)
MD5, SHA-1 은 충돌 공격이 가능하고 DES, RC4 는 키 길이·구조적 약점으로 안전하지 않습니다.
조치 방법: 무결성 확인에는 SHA-256 이상, 암호화에는 AES-GCM(cryptography 패키지의 AESGCM)을 사용합니다. 비밀번호 저장은 bcrypt, argon2, PBKDF2 처럼 솔트와 반복을 갖춘 해시를 사용합니다. 보안 목적이 아닌 체크섬이라면 hashlib.md5(usedforsecurity=False) 로 의도를 명시합니다.
TrustChain 룰: TC-CRYPTO-001.

## 적절하지 않은 난수 값 사용 (CWE-330)
random 모듈은 예측 가능한 의사난수이므로 세션 ID, 토큰, 비밀번호 재설정 코드, OTP 에 사용하면 추측될 수 있습니다.
조치 방법: secrets.token_urlsafe(32), secrets.token_hex, secrets.randbelow 를 사용합니다.
TrustChain 룰: TC-RAND-001.

## 부적절한 인증서 유효성 검증 (CWE-295)
requests/httpx 에서 verify=False 를 지정하거나 ssl._create_unverified_context 를 사용하면 중간자 공격으로 통신 내용이 탈취·변조될 수 있습니다.
조치 방법: 기본 인증서 검증을 유지하고, 사설 CA 는 verify="/etc/ssl/private-ca.pem" 처럼 CA 번들을 지정합니다.
TrustChain 룰: TC-TLS-001.

## 로그를 통한 중요정보 노출 (CWE-532)
비밀번호·토큰·개인정보가 로그에 남으면 로그 수집 시스템 접근자에게 노출됩니다.
조치 방법: 로그 필터에서 토큰·이메일·주민등록번호 패턴을 마스킹하고, 인증 정보를 로그 메시지에 포함하지 않습니다. TrustChain 은 core.logging.MaskingFilter 로 자체 로그를 마스킹합니다.
TrustChain 룰: TC-LOG-001.

## 무결성 검사 없는 코드 다운로드 (CWE-494)
curl ... | sh 처럼 원격 스크립트를 검증 없이 실행하거나, 해시를 고정하지 않은 의존성을 설치하면 배포 서버가 변조되었을 때 악성 코드가 그대로 실행됩니다.
조치 방법: 내려받은 파일의 SHA-256 체크섬이나 서명을 검증한 뒤 실행합니다. pip 는 --require-hashes 와 해시가 고정된 requirements.txt 를 사용하고, GitHub Actions 서드파티 액션은 커밋 SHA 로 고정합니다.
TrustChain 룰: TC-IMG-003, 의존성 해시 고정 점검.
