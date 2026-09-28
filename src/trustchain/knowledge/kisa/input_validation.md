# KISA 시큐어코딩 가이드(Python) 요약 - 입력데이터 검증 및 표현

> TrustChain AI 팀이 행정안전부·KISA 「Python 시큐어코딩 가이드」의 보안약점 항목을 참고해 작성한 요약·조치 안내입니다.
> 원문 해설과 전체 항목은 KISA 발간 가이드를 확인하세요.

## SQL 삽입 (CWE-89)
외부 입력값을 문자열 결합, f-string, % 포맷, str.format 으로 SQL 문에 넣으면 공격자가 쿼리 구조를 바꿔 인증 우회나 데이터 유출을 일으킬 수 있습니다.
조치 방법: DB API 의 파라미터 바인딩(cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,)))을 사용합니다. SQLAlchemy 는 ORM 쿼리 또는 text() 에 :name 바인딩 파라미터를 사용합니다. 테이블명·정렬 컬럼처럼 바인딩할 수 없는 값은 허용 목록으로 검증합니다.
TrustChain 룰: TC-SQL-001 은 execute/executemany/text/read_sql 에 동적 문자열이 전달되면 탐지합니다.

## 운영체제 명령어 삽입 (CWE-78)
os.system, os.popen, subprocess 의 shell=True 에 외부 입력이 섞이면 ; && | 같은 셸 메타문자로 임의 명령이 실행됩니다.
조치 방법: shell=True 를 쓰지 말고 subprocess.run(["ping", "-c", "1", host]) 처럼 인자 리스트로 실행합니다. 입력값은 허용 목록(예: 호스트명 정규식)으로 검증하고, 꼭 셸이 필요하면 shlex.quote 로 이스케이프합니다.
TrustChain 룰: TC-CMD-001.

## 코드 삽입 (CWE-95)
eval, exec, compile 에 외부 입력을 전달하면 공격자가 파이썬 코드를 그대로 실행할 수 있습니다.
조치 방법: 리터럴 파싱은 ast.literal_eval, 데이터 교환은 json.loads 를 사용합니다. 수식 계산이 필요하면 허용된 연산자만 처리하는 파서를 직접 구현합니다.
TrustChain 룰: TC-CODE-001.

## 경로 조작 및 자원 삽입 (CWE-22)
파일 이름이나 경로에 ../ 같은 상위 디렉터리 참조가 들어오면 의도하지 않은 파일을 읽거나 덮어쓸 수 있습니다.
조치 방법: os.path.basename 또는 werkzeug.utils.secure_filename 으로 파일명을 정규화하고, Path(BASE_DIR / name).resolve() 결과가 is_relative_to(BASE_DIR) 인지 확인합니다. 업로드 파일은 확장자·MIME·크기를 제한하고 저장 이름은 서버가 생성합니다.
TrustChain 룰: TC-PATH-001 은 웹 핸들러 파라미터가 open/FileResponse/send_file 경로로 쓰이면 탐지합니다.

## 입력값 검증 누락 (CWE-20)
요청 본문을 dict 나 Any 로 받거나 request.json() 을 직접 사용하면 형식·길이·범위 검증이 빠지기 쉽습니다.
조치 방법: FastAPI 에서는 pydantic 모델(BaseModel)로 필드 타입, max_length, 정규식 패턴, 숫자 범위(ge/le)를 선언하고 extra="forbid" 로 정의되지 않은 필드를 거부합니다.
TrustChain 룰: TC-INPUT-001.

## 부적절한 XML 외부개체 참조 (CWE-611)
표준 xml 모듈로 신뢰할 수 없는 XML 을 파싱하면 외부 엔티티(XXE)나 엔티티 확장(Billion Laughs) 공격에 노출될 수 있습니다.
조치 방법: defusedxml.ElementTree 를 사용하거나 lxml 에서 resolve_entities=False, no_network=True 로 파서를 설정합니다.
TrustChain 룰: TC-XML-001.
