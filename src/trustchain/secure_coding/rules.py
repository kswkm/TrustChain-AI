"""F1. KISA 시큐어코딩 가이드(Python) 기준 자체 점검 룰.

외부 도구(Semgrep·Bandit)가 없는 개발자 PC 에서도 커밋 시점에 동작하도록
표준 라이브러리 ast 만으로 구현한다. 룰은 '위험 API(sink)'와 '신뢰할 수 없는
값(비상수 문자열 조합, 웹 핸들러 파라미터)'의 결합을 찾는 경량 오염 분석이다.

억제 : 해당 줄에 `# trustchain: ignore` 또는 `# trustchain: ignore[TC-SQL-001]`.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from typing import Callable, Iterable

from trustchain.core.findings import Finding, Severity


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: Severity
    cwe: str
    kisa: str
    fix: str


RULES: dict[str, Rule] = {
    r.id: r
    for r in [
        Rule(
            "TC-SQL-001", "SQL 삽입", Severity.HIGH, "CWE-89", "입력데이터 검증 및 표현 - SQL 삽입",
            "문자열 결합 대신 파라미터 바인딩을 사용하세요.\n"
            "  cur.execute(\"SELECT * FROM users WHERE id = %s\", (user_id,))\n"
            "  # SQLAlchemy: session.execute(text(\"... WHERE id = :id\"), {\"id\": user_id})",
        ),
        Rule(
            "TC-CMD-001", "운영체제 명령어 삽입", Severity.HIGH, "CWE-78", "입력데이터 검증 및 표현 - 운영체제 명령어 삽입",
            "shell=True 와 문자열 명령 대신 인자 리스트를 사용하고 허용 목록으로 검증하세요.\n"
            "  subprocess.run([\"ping\", \"-c\", \"1\", host], check=True)",
        ),
        Rule(
            "TC-CODE-001", "코드 삽입", Severity.HIGH, "CWE-95", "입력데이터 검증 및 표현 - 코드 삽입",
            "eval/exec 대신 ast.literal_eval 또는 명시적 파서를 사용하세요.\n  value = ast.literal_eval(expr)",
        ),
        Rule(
            "TC-PATH-001", "경로 조작 및 자원 삽입", Severity.HIGH, "CWE-22",
            "입력데이터 검증 및 표현 - 경로 조작 및 자원 삽입",
            "파일명을 정규화하고 기준 디렉터리 밖을 가리키지 않는지 확인하세요.\n"
            "  p = (BASE_DIR / os.path.basename(name)).resolve()\n"
            "  if not p.is_relative_to(BASE_DIR): raise ValueError(\"잘못된 경로\")",
        ),
        Rule(
            "TC-INPUT-001", "입력값 검증 누락", Severity.MEDIUM, "CWE-20", "입력데이터 검증 및 표현 - 입력값 검증",
            "요청 본문을 dict/Any 로 받지 말고 pydantic 모델로 형식·길이·범위를 검증하세요.\n"
            "  class Item(BaseModel):\n      name: constr(max_length=100)\n  def create(item: Item): ...",
        ),
        Rule(
            "TC-SECRET-001", "하드코드된 중요정보", Severity.HIGH, "CWE-798", "보안기능 - 하드코드된 중요정보",
            "비밀정보는 환경변수·시크릿 저장소에서 읽으세요.\n  password = os.environ[\"DB_PASSWORD\"]",
        ),
        Rule(
            "TC-SECRET-002", "소스에 포함된 자격증명 토큰", Severity.CRITICAL, "CWE-798",
            "보안기능 - 하드코드된 중요정보",
            "즉시 토큰을 폐기(revoke)·재발급하고, 저장소 이력에서 제거한 뒤 GitHub Secrets/OIDC 를 사용하세요.",
        ),
        Rule(
            "TC-DESER-001", "신뢰할 수 없는 데이터의 역직렬화", Severity.HIGH, "CWE-502",
            "보안기능 - 신뢰할 수 없는 데이터의 역직렬화",
            "pickle 계열 로드를 금지하고 JSON·safetensors 등 코드 실행이 없는 형식을 사용하세요.\n"
            "  yaml.safe_load(f) / torch.load(p, weights_only=True) / safetensors.torch.load_file(p)",
        ),
        Rule(
            "TC-CRYPTO-001", "취약한 암호화 알고리즘 사용", Severity.MEDIUM, "CWE-327",
            "보안기능 - 취약한 암호화 알고리즘 사용",
            "MD5/SHA-1/DES 대신 SHA-256 이상, AES-GCM 을 사용하세요. 비밀번호는 bcrypt/argon2/PBKDF2 로 해시하세요.",
        ),
        Rule(
            "TC-RAND-001", "적절하지 않은 난수 값 사용", Severity.MEDIUM, "CWE-330", "보안기능 - 적절하지 않은 난수 값 사용",
            "보안 용도 난수는 secrets 모듈을 사용하세요.\n  token = secrets.token_urlsafe(32)",
        ),
        Rule(
            "TC-TLS-001", "부적절한 인증서 유효성 검증", Severity.HIGH, "CWE-295", "보안기능 - 부적절한 인증서 유효성 검증",
            "verify=False 를 제거하고, 사설 CA 는 verify=\"/path/ca.pem\" 으로 지정하세요.",
        ),
        Rule(
            "TC-DEBUG-001", "제거되지 않고 남은 디버그 코드", Severity.MEDIUM, "CWE-489",
            "캡슐화 - 제거되지 않고 남은 디버그 코드",
            "운영 환경에서는 debug=False 로 실행하고 설정값을 환경변수로 분리하세요.",
        ),
        Rule(
            "TC-ERR-001", "오류 메시지 정보노출", Severity.LOW, "CWE-209", "에러처리 - 오류 메시지 정보노출",
            "예외 상세·스택트레이스는 서버 로그에만 남기고 사용자에게는 일반화된 메시지를 반환하세요.",
        ),
        Rule(
            "TC-LOG-001", "로그를 통한 중요정보 노출", Severity.MEDIUM, "CWE-532", "보안기능 - 암호화되지 않은 중요정보",
            "비밀번호·토큰을 로그에 남기지 말고, 필요하면 마스킹하세요.",
        ),
        Rule(
            "TC-XML-001", "부적절한 XML 외부개체 참조", Severity.MEDIUM, "CWE-611",
            "입력데이터 검증 및 표현 - 부적절한 XML 외부개체 참조",
            "외부 XML 은 defusedxml 로 파싱하세요.\n  from defusedxml.ElementTree import fromstring",
        ),
        Rule(
            "TC-TEMP-001", "경쟁조건: 안전하지 않은 임시파일", Severity.LOW, "CWE-377", "시간 및 상태 - 경쟁조건",
            "tempfile.mktemp 대신 tempfile.NamedTemporaryFile / mkstemp 를 사용하세요.",
        ),
    ]
}

SECRET_NAME = re.compile(
    r"(?i)(^|_)(pass(word|wd)?|pwd|secret|token|api_?key|access_?key|private_?key|client_?secret|auth)($|_)"
)
_PLACEHOLDER = re.compile(r"(?i)^(\*+|x+|<.*>|\$\{.*\}|your[_-].*|changeme_placeholder|example|dummy|test|none|null)$")

# 텍스트 전체에서 찾는 고신뢰 자격증명 패턴 (언어 무관)
TOKEN_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("AWS Access Key", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("GitHub 토큰", re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})\b")),
    ("Slack 토큰", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{20,}\b")),
    ("개인키", re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA |)PRIVATE KEY-----")),
    ("Google API Key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("Anthropic/OpenAI API Key", re.compile(r"\bsk-(ant-api\d{2}-)?[A-Za-z0-9_\-]{32,}\b")),
]

ROUTE_DECORATORS = {"get", "post", "put", "delete", "patch", "route", "api_route", "websocket"}
PATH_SANITIZERS = {"basename", "secure_filename", "is_relative_to", "commonpath", "realpath", "normpath"}
WEAK_HASHES = {"hashlib.md5", "hashlib.sha1", "Crypto.Hash.MD5.new", "Crypto.Hash.SHA.new"}
DESER_CALLS = {
    "pickle.load", "pickle.loads", "pickle.Unpickler", "_pickle.load", "_pickle.loads", "cPickle.load",
    "cPickle.loads", "dill.load", "dill.loads", "joblib.load", "shelve.open", "marshal.load", "marshal.loads",
    "pandas.read_pickle", "yaml.unsafe_load", "yaml.full_load", "jsonpickle.decode",
}


def _dotted(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        return _dotted(node.func)
    return None


def _kw(call: ast.Call, name: str) -> ast.expr | None:
    for k in call.keywords:
        if k.arg == name:
            return k.value
    return None


def _is_const(node: ast.AST | None, value: object = ...) -> bool:
    if not isinstance(node, ast.Constant):
        return False
    return value is ... or node.value == value


def _names_in(node: ast.AST) -> set[str]:
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}


class _Analyzer(ast.NodeVisitor):
    def __init__(self, path: str, lines: list[str]):
        self.path = path
        self.lines = lines
        self.findings: list[Finding] = []
        self.aliases: dict[str, str] = {}
        # 함수 스코프 상태
        self.tainted_strings: set[str] = set()  # 비상수 조합으로 만든 문자열 변수
        self.params: set[str] = set()  # 웹 핸들러 파라미터 (외부 입력)
        self.user_vars: set[str] = set()  # 요청 값(request.args 등)을 담은 지역 변수 (외부 입력)
        self.sanitized: bool = False
        self.in_route = False

    # ---------- 공통 ----------
    def resolve(self, node: ast.AST) -> str:
        d = _dotted(node) or ""
        head, _, rest = d.partition(".")
        if head in self.aliases:
            return self.aliases[head] + ("." + rest if rest else "")
        return d

    def report(self, rule_id: str, node: ast.AST, message: str, severity: Severity | None = None) -> None:
        line = getattr(node, "lineno", None)
        if line and self._suppressed(line, rule_id):
            return
        r = RULES[rule_id]
        self.findings.append(
            Finding(
                rule_id=r.id, title=r.title, severity=severity or r.severity, message=message, category="code",
                file=self.path, line=line, cwe=r.cwe, kisa=r.kisa, fix=r.fix,
            )
        )

    def _suppressed(self, line: int, rule_id: str) -> bool:
        if not (0 < line <= len(self.lines)):
            return False
        text = self.lines[line - 1]
        m = re.search(r"#\s*(trustchain:\s*ignore(\[([A-Z0-9\-, ]+)\])?|nosec)", text)
        if not m:
            return False
        ids = m.group(3)
        return not ids or rule_id in [i.strip() for i in ids.split(",")]

    def is_dynamic_str(self, node: ast.AST | None) -> bool:
        """비상수 값이 섞여 만들어진 문자열인가 (f-string, +, %, .format, 오염 변수)."""
        if node is None:
            return False
        if isinstance(node, ast.JoinedStr):
            return any(isinstance(v, ast.FormattedValue) for v in node.values)
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
            return not (_is_const(node.left) and _is_const(node.right))
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
            return bool(node.args or node.keywords)
        if isinstance(node, ast.Name):
            return node.id in self.tainted_strings
        return False

    def from_user_input(self, node: ast.AST) -> bool:
        names = _names_in(node)
        if names & (self.params | self.user_vars):
            return True
        # Flask / Django 요청 객체
        for n in ast.walk(node):
            d = _dotted(n) if isinstance(n, (ast.Attribute, ast.Call)) else None
            if d and re.match(r"^request\.(args|form|values|files|json|GET|POST|data|query_params|path_params)", d):
                return True
        return False

    # ---------- import 별칭 ----------
    def visit_Import(self, node: ast.Import) -> None:
        for a in node.names:
            self.aliases[a.asname or a.name.split(".")[0]] = a.name if a.asname else a.name.split(".")[0]

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module:
            for a in node.names:
                self.aliases[a.asname or a.name] = f"{node.module}.{a.name}"

    # ---------- 함수 스코프 ----------
    def _visit_func(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        saved = (self.tainted_strings, self.params, self.sanitized, self.in_route, self.user_vars)
        self.tainted_strings = set()
        self.user_vars = set()
        is_route = any(self._is_route_decorator(d) for d in node.decorator_list)
        self.in_route = is_route
        self.params = {a.arg for a in node.args.args + node.args.kwonlyargs} - {"self", "cls"} if is_route else set()
        self.sanitized = any(
            isinstance(n, (ast.Call, ast.Attribute)) and (_dotted(n) or "").split(".")[-1] in PATH_SANITIZERS
            for n in ast.walk(node)
        )
        if is_route:
            self._check_input_validation(node)
        self.generic_visit(node)
        self.tainted_strings, self.params, self.sanitized, self.in_route, self.user_vars = saved

    visit_FunctionDef = _visit_func
    visit_AsyncFunctionDef = _visit_func

    def _is_route_decorator(self, dec: ast.AST) -> bool:
        target = dec.func if isinstance(dec, ast.Call) else dec
        return isinstance(target, ast.Attribute) and target.attr in ROUTE_DECORATORS

    def _check_input_validation(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        for a in node.args.args + node.args.kwonlyargs:
            ann = a.annotation
            ann_name = _dotted(ann) if ann is not None else None
            if ann_name in ("dict", "Dict", "typing.Dict", "Any", "typing.Any", "object"):
                self.report(
                    "TC-INPUT-001", a,
                    f"웹 핸들러 '{node.name}' 의 파라미터 '{a.arg}' 가 {ann_name} 타입으로 선언되어 형식 검증이 없습니다.",
                )
        for n in ast.walk(node):
            if isinstance(n, ast.Await) and isinstance(n.value, ast.Call):
                d = _dotted(n.value.func) or ""
                if d.endswith(".json") and d.split(".")[0] in {a.arg for a in node.args.args}:
                    self.report(
                        "TC-INPUT-001", n,
                        f"웹 핸들러 '{node.name}' 가 요청 본문을 스키마 검증 없이 직접 파싱합니다(request.json()).",
                    )

    # ---------- 대입 : 오염 추적 + 하드코딩 비밀정보 ----------
    def visit_Assign(self, node: ast.Assign) -> None:
        for t in node.targets:
            self._track_assign(t, node.value)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None:
            self._track_assign(node.target, node.value)
        self.generic_visit(node)

    def _track_assign(self, target: ast.AST, value: ast.AST) -> None:
        if isinstance(target, ast.Name):
            user = self.in_route and not _is_const(value) and self.from_user_input(value)
            if user:
                self.user_vars.add(target.id)
            else:
                self.user_vars.discard(target.id)
            if self.is_dynamic_str(value) or user:
                self.tainted_strings.add(target.id)
            else:
                self.tainted_strings.discard(target.id)
            self._check_secret(target.id, value)
            self._check_random(target.id, value)
        elif isinstance(target, ast.Attribute):
            self._check_secret(target.attr, value)

    def _check_secret(self, name: str, value: ast.AST) -> None:
        if not SECRET_NAME.search(name) or not isinstance(value, ast.Constant) or not isinstance(value.value, str):
            return
        v = value.value
        if len(v) < 6 or _PLACEHOLDER.match(v) or " " in v.strip() and len(v.split()) > 3:
            return
        self.report("TC-SECRET-001", value, f"'{name}' 에 비밀정보로 보이는 문자열이 하드코딩되어 있습니다.")

    def _check_random(self, name: str, value: ast.AST) -> None:
        if not SECRET_NAME.search(name) and not re.search(r"(?i)(otp|nonce|salt|session|csrf)", name):
            return
        for n in ast.walk(value):
            if isinstance(n, ast.Call) and self.resolve(n.func).startswith("random."):
                self.report("TC-RAND-001", n, f"보안 값 '{name}' 을 예측 가능한 random 모듈로 생성합니다.")
                return

    def visit_Dict(self, node: ast.Dict) -> None:
        for k, v in zip(node.keys, node.values):
            if isinstance(k, ast.Constant) and isinstance(k.value, str) and v is not None:
                self._check_secret(k.value, v)
        self.generic_visit(node)

    # ---------- 호출 : sink 점검 ----------
    def visit_Call(self, node: ast.Call) -> None:
        name = self.resolve(node.func)
        short = name.split(".")[-1]
        for check in self._call_checks:
            check(self, node, name, short)
        for k in node.keywords:
            if k.arg:
                self._check_secret(k.arg, k.value)
        self.generic_visit(node)

    def _chk_sql(self, node: ast.Call, name: str, short: str) -> None:
        if short not in {"execute", "executemany", "executescript", "raw", "text", "read_sql", "read_sql_query", "exec_driver_sql"}:
            return
        if not node.args:
            return
        q = node.args[0]
        if self.is_dynamic_str(q):
            self.report("TC-SQL-001", node, f"{short}() 에 문자열 조합으로 만든 쿼리가 전달됩니다. 파라미터 바인딩을 사용하세요.")

    def _chk_cmd(self, node: ast.Call, name: str, short: str) -> None:
        arg0 = node.args[0] if node.args else _kw(node, "args")
        if name in {"os.system", "os.popen", "commands.getoutput", "subprocess.getoutput", "subprocess.getstatusoutput"}:
            if arg0 is not None and not _is_const(arg0):
                self.report("TC-CMD-001", node, f"{name}() 에 동적으로 만든 명령어가 전달됩니다.")
            return
        if name.startswith("subprocess.") and short in {"run", "call", "check_call", "check_output", "Popen"}:
            if _is_const(_kw(node, "shell"), True):
                if arg0 is not None and not _is_const(arg0):
                    self.report("TC-CMD-001", node, f"shell=True 인 {name}() 에 동적 명령어가 전달됩니다.")
                else:
                    self.report("TC-CMD-001", node, f"{name}() 가 shell=True 로 실행됩니다.", Severity.LOW)

    def _chk_code(self, node: ast.Call, name: str, short: str) -> None:
        if name in {"eval", "exec", "builtins.eval", "builtins.exec"} and node.args and not _is_const(node.args[0]):
            self.report("TC-CODE-001", node, f"{name}() 에 동적 값이 전달됩니다.")

    def _chk_path(self, node: ast.Call, name: str, short: str) -> None:
        if not self.in_route or self.sanitized:
            return
        sinks = {"open", "io.open", "pathlib.Path", "Path", "os.remove", "os.unlink", "shutil.rmtree",
                 "send_file", "flask.send_file", "fastapi.responses.FileResponse", "FileResponse",
                 "starlette.responses.FileResponse", "os.path.join"}
        if name in sinks or short in {"send_file", "FileResponse"}:
            if any(self.from_user_input(a) or self.is_dynamic_str(a) and _names_in(a) & self.params for a in node.args):
                self.report("TC-PATH-001", node, f"외부 입력이 검증 없이 파일 경로로 사용됩니다: {name}()")

    def _chk_deser(self, node: ast.Call, name: str, short: str) -> None:
        if name in DESER_CALLS:
            self.report("TC-DESER-001", node, f"{name}() 는 신뢰할 수 없는 데이터를 로드할 때 임의 코드가 실행될 수 있습니다.")
        elif name == "yaml.load":
            loader = _kw(node, "Loader") or (node.args[1] if len(node.args) > 1 else None)
            if loader is None or "Safe" not in (self.resolve(loader) or ""):
                self.report("TC-DESER-001", node, "yaml.load() 가 SafeLoader 없이 호출됩니다.")
        elif name == "torch.load" and not _is_const(_kw(node, "weights_only"), True):
            self.report("TC-DESER-001", node, "torch.load() 가 weights_only=True 없이 호출되어 pickle 코드가 실행될 수 있습니다.")
        elif short == "load" and name.startswith(("numpy.", "np.")) and _is_const(_kw(node, "allow_pickle"), True):
            self.report("TC-DESER-001", node, "numpy.load(allow_pickle=True) 는 pickle 객체를 역직렬화합니다.")
        elif short == "load_model" and _is_const(_kw(node, "safe_mode"), False):
            self.report("TC-DESER-001", node, "Keras load_model(safe_mode=False) 는 Lambda 레이어의 임의 코드를 허용합니다.")

    def _chk_crypto(self, node: ast.Call, name: str, short: str) -> None:
        if name in WEAK_HASHES and not _is_const(_kw(node, "usedforsecurity"), False):
            self.report("TC-CRYPTO-001", node, f"{name}() 는 충돌 공격에 취약한 해시입니다.")
        elif name == "hashlib.new" and node.args and isinstance(node.args[0], ast.Constant) and str(
            node.args[0].value
        ).lower() in {"md5", "sha1", "md4"}:
            self.report("TC-CRYPTO-001", node, f"hashlib.new('{node.args[0].value}') 는 취약한 해시입니다.")
        elif name.startswith(("Crypto.Cipher.DES", "Crypto.Cipher.ARC4", "Crypto.Cipher.Blowfish")):
            self.report("TC-CRYPTO-001", node, f"{name} 는 취약한 암호 알고리즘입니다.")

    def _chk_tls(self, node: ast.Call, name: str, short: str) -> None:
        if _is_const(_kw(node, "verify"), False):
            self.report("TC-TLS-001", node, f"{name or short}() 에서 TLS 인증서 검증이 비활성화(verify=False)되어 있습니다.")
        if name in {"ssl._create_unverified_context"}:
            self.report("TC-TLS-001", node, "검증하지 않는 SSL 컨텍스트를 생성합니다.")

    def _chk_debug(self, node: ast.Call, name: str, short: str) -> None:
        if short == "run" and _is_const(_kw(node, "debug"), True):
            self.report("TC-DEBUG-001", node, "애플리케이션이 debug=True 로 실행됩니다.")

    def _chk_log(self, node: ast.Call, name: str, short: str) -> None:
        if short not in {"debug", "info", "warning", "error", "critical", "exception", "print", "log"}:
            return
        if short != "print" and not re.search(r"(?i)(log|logger|logging)", name):
            return
        for a in node.args:
            for n in ast.walk(a):
                if isinstance(n, ast.Name) and SECRET_NAME.search(n.id):
                    self.report("TC-LOG-001", node, f"로그/출력에 중요정보 변수 '{n.id}' 가 포함됩니다.")
                    return

    def _chk_err(self, node: ast.Call, name: str, short: str) -> None:
        if self.in_route and name in {"traceback.format_exc", "traceback.format_exception"}:
            self.report("TC-ERR-001", node, "웹 핸들러에서 스택트레이스를 생성합니다. 응답에 포함하지 마세요.")

    def _chk_xml(self, node: ast.Call, name: str, short: str) -> None:
        if name in {"xml.etree.ElementTree.parse", "xml.etree.ElementTree.fromstring", "xml.dom.minidom.parse",
                    "xml.dom.minidom.parseString", "xml.sax.parse", "lxml.etree.parse", "lxml.etree.fromstring"}:
            self.report("TC-XML-001", node, f"{name}() 는 외부 XML 파싱 시 XXE/엔티티 확장 공격에 노출될 수 있습니다.")

    def _chk_temp(self, node: ast.Call, name: str, short: str) -> None:
        if name == "tempfile.mktemp":
            self.report("TC-TEMP-001", node, "tempfile.mktemp() 는 경쟁 조건에 취약합니다.")

    _call_checks: list[Callable[["_Analyzer", ast.Call, str, str], None]] = [
        _chk_sql, _chk_cmd, _chk_code, _chk_path, _chk_deser, _chk_crypto, _chk_tls,
        _chk_debug, _chk_log, _chk_err, _chk_xml, _chk_temp,
    ]

    # 핸들러에서 예외 문자열을 그대로 반환
    def visit_Return(self, node: ast.Return) -> None:
        if self.in_route and node.value is not None:
            for n in ast.walk(node.value):
                if isinstance(n, ast.Call) and _dotted(n.func) in ("str", "repr") and n.args and isinstance(
                    n.args[0], ast.Name
                ) and n.args[0].id in ("e", "exc", "err", "ex", "error"):
                    self.report("TC-ERR-001", node, "예외 메시지를 그대로 응답으로 반환합니다.")
                    break
        self.generic_visit(node)


def analyze_python(source: str, path: str) -> list[Finding]:
    try:
        tree = ast.parse(source, filename=path)
    except (SyntaxError, ValueError):
        return []
    a = _Analyzer(path, source.splitlines())
    a.visit(tree)
    return a.findings


def scan_text_for_tokens(text: str, path: str) -> Iterable[Finding]:
    r = RULES["TC-SECRET-002"]
    lines = text.splitlines()
    for i, line in enumerate(lines, 1):
        if "trustchain: ignore" in line:
            continue
        for label, pat in TOKEN_PATTERNS:
            if pat.search(line):
                yield Finding(
                    rule_id=r.id, title=r.title, severity=r.severity, category="code", file=path, line=i,
                    message=f"{label} 로 보이는 자격증명이 소스에 포함되어 있습니다.", cwe=r.cwe, kisa=r.kisa, fix=r.fix,
                )
                break
