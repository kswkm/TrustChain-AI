# KISA 시큐어코딩 가이드(Python) 요약 - 에러처리·캡슐화·시간 및 상태

> TrustChain AI 팀이 KISA 「Python 시큐어코딩 가이드」 해당 항목을 참고해 작성한 요약입니다.

## 오류 메시지 정보노출 (CWE-209)
스택트레이스, 예외 메시지(str(e)), 내부 경로·쿼리를 사용자에게 그대로 반환하면 공격자가 시스템 구조를 파악하는 데 쓰입니다.
조치 방법: 예외 상세는 서버 로그에만 기록하고 사용자에게는 "요청을 처리할 수 없습니다" 같은 일반 메시지와 추적용 요청 ID 만 반환합니다. FastAPI 는 전역 exception_handler 로 응답 형식을 통일합니다.
TrustChain 룰: TC-ERR-001.

## 제거되지 않고 남은 디버그 코드 (CWE-489)
Flask app.run(debug=True) 는 브라우저에서 파이썬 코드를 실행할 수 있는 디버거를 노출합니다. Django DEBUG=True 는 설정값과 스택트레이스를 노출합니다.
조치 방법: 디버그 설정은 환경변수로 분리하고 운영 배포에서는 항상 비활성화합니다. 운영 서버는 gunicorn/uvicorn 등 운영용 서버로 실행합니다.
TrustChain 룰: TC-DEBUG-001.

## 경쟁조건: 안전하지 않은 임시파일 (CWE-377)
tempfile.mktemp 는 이름만 만들고 파일은 만들지 않으므로, 생성 전에 공격자가 같은 이름의 파일이나 심볼릭 링크를 만들 수 있습니다.
조치 방법: tempfile.NamedTemporaryFile, tempfile.mkstemp, TemporaryDirectory 를 사용합니다.
TrustChain 룰: TC-TEMP-001.
