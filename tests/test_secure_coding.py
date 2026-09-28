from trustchain.core.config import Config
from trustchain.secure_coding.rules import analyze_python, scan_text_for_tokens
from trustchain.secure_coding.runner import run_builtin


def ids(src: str) -> list[str]:
    return [f.rule_id for f in analyze_python(src, "x.py")]


def test_sql_injection_variants():
    src = '''
def q(cur, uid, name):
    sql = "SELECT * FROM u WHERE id=" + uid
    cur.execute(sql)
    cur.execute(f"SELECT * FROM u WHERE name='{name}'")
    cur.execute("SELECT * FROM u WHERE name='%s'" % name)
    cur.execute("SELECT * FROM u WHERE id={}".format(uid))
'''
    assert ids(src).count("TC-SQL-001") == 4


def test_sql_parameter_binding_is_safe():
    src = '''
def q(cur, uid):
    cur.execute("SELECT * FROM u WHERE id = %s", (uid,))
    cur.execute("SELECT 1")
'''
    assert "TC-SQL-001" not in ids(src)


def test_reassigned_variable_clears_taint():
    src = '''
def q(cur, uid):
    sql = "SELECT " + uid
    sql = "SELECT 1"
    cur.execute(sql)
'''
    assert "TC-SQL-001" not in ids(src)


def test_command_injection():
    src = '''
import os, subprocess as sp
def f(host):
    os.system("ping " + host)
    sp.run(f"ls {host}", shell=True)
    sp.run(["ls", host])
'''
    found = ids(src)
    assert found.count("TC-CMD-001") == 2


def test_deserialization_rules():
    src = '''
import pickle, yaml, torch, joblib
from pickle import loads as L
def f(b, p):
    pickle.loads(b)
    L(b)
    yaml.load(b)
    yaml.load(b, Loader=yaml.SafeLoader)
    yaml.safe_load(b)
    torch.load(p)
    torch.load(p, weights_only=True)
    joblib.load(p)
'''
    assert ids(src).count("TC-DESER-001") == 5


def test_hardcoded_secret_and_placeholder():
    src = '''
DB_PASSWORD = "Sup3rS3cret!"
API_KEY = ""
TOKEN = "<your-token>"
config = {"password": "hunter2hunter2"}
connect(password="abcdef123")
'''
    assert ids(src).count("TC-SECRET-001") == 3


def test_token_patterns():
    # 가짜 자격증명은 나눠 적어 저장소 자체 점검(dogfooding)에 걸리지 않게 한다
    text = 'aws = "AKIA' + 'ABCDEFGHIJKLMNOP"\nkey = "-----BEGIN RSA ' + 'PRIVATE KEY-----"\n'
    found = list(scan_text_for_tokens(text, "a.py"))
    assert [f.line for f in found] == [1, 2]
    assert all(f.severity.value == "CRITICAL" for f in found)


def test_route_path_traversal_and_input_validation():
    src = '''
from fastapi import FastAPI, Request
app = FastAPI()
@app.get("/file")
def read(name: str, body: dict):
    return open("/data/" + name).read()

@app.get("/safe")
def safe(name: str):
    import os
    return open(os.path.join("/data", os.path.basename(name))).read()

@app.post("/raw")
async def raw(request: Request):
    return await request.json()
'''
    found = ids(src)
    assert found.count("TC-PATH-001") == 1
    assert found.count("TC-INPUT-001") == 2


def test_misc_rules():
    src = '''
import hashlib, random, requests, tempfile
import xml.etree.ElementTree as ET
def f(x, app, logger, password):
    hashlib.md5(x)
    hashlib.md5(x, usedforsecurity=False)
    token = random.randint(0, 999999)
    requests.get("https://a", verify=False)
    app.run(debug=True)
    eval(x)
    eval("1+1")
    tempfile.mktemp()
    ET.fromstring(x)
    logger.info(f"login {password}")
'''
    found = ids(src)
    for rid in ("TC-CRYPTO-001", "TC-RAND-001", "TC-TLS-001", "TC-DEBUG-001", "TC-CODE-001", "TC-TEMP-001",
                "TC-XML-001", "TC-LOG-001"):
        assert found.count(rid) == 1, rid


def test_suppression_comment():
    src = '''
import pickle
def f(b):
    pickle.loads(b)  # trustchain: ignore[TC-DESER-001]
    pickle.loads(b)  # trustchain: ignore[TC-SQL-001]
'''
    assert ids(src).count("TC-DESER-001") == 1


def test_syntax_error_is_ignored():
    assert analyze_python("def (:", "bad.py") == []


def test_runner_walks_and_disables(tmp_path):
    (tmp_path / "a.py").write_text("import pickle\npickle.loads(b'')\n", encoding="utf-8")
    (tmp_path / ".env").write_text("GITHUB=ghp_" + "a" * 36 + "\n", encoding="utf-8")
    cfg = Config(root=tmp_path)
    got = {f.rule_id for f in run_builtin([tmp_path], cfg)}
    assert {"TC-DESER-001", "TC-SECRET-002"} <= got
    cfg.disabled_rules = ["TC-DESER-001"]
    assert "TC-DESER-001" not in {f.rule_id for f in run_builtin([tmp_path], cfg)}
