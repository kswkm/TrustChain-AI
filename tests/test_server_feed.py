import time

import pytest
from fastapi.testclient import TestClient

from trustchain.feed.monitor import FeedMonitor, parse_modified_csv
from trustchain.feed.notify import MemoryNotifier, SlackNotifier
from trustchain.server.app import create_app
from trustchain.server.auth import create_token

SBOM = {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [
    {"type": "library", "name": "PyYAML", "version": "5.3.1", "purl": "pkg:pypi/pyyaml@5.3.1"},
    {"type": "library", "name": "requests", "version": "2.31.0", "purl": "pkg:pypi/requests@2.31.0"},
    {"type": "library", "name": "openssl", "version": "3.0.1", "purl": "pkg:deb/debian/openssl@3.0.1"},
]}
DIGEST = "sha256:" + "a" * 64
VULN = {"id": "PYSEC-TEST-1", "summary": "PyYAML full_load RCE", "aliases": ["CVE-2020-14343"],
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
        "affected": [{"package": {"ecosystem": "PyPI", "name": "PyYAML"},
                      "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "5.4"}]}]}]}


class NoNetHTTP:
    """피드 모니터용 가짜 HTTP (네트워크 차단)."""

    def get_text(self, url, max_bytes=0):
        return "2026-09-01T00:00:00Z,PYSEC-TEST-1\n2026-08-01T00:00:00Z,OLD-1\n"

    def get_json(self, url, **kw):
        return VULN if url.endswith("PYSEC-TEST-1") else {"__status__": 404}

    def post_json(self, url, payload, **kw):
        return {"results": [{"vulns": [{"id": "PYSEC-TEST-1"}]} if q["package"]["name"].lower() == "pyyaml"
                            else {} for q in payload["queries"]]}


@pytest.fixture
def env(tmp_path):
    url = f"sqlite:///{(tmp_path / 't.db').as_posix()}"
    notifier = MemoryNotifier()
    app = create_app(url, monitor=None, start_scheduler=False)
    sf = app.state.tc.sf
    mon = FeedMonitor(sf, notifier, http=NoNetHTTP())
    app.state.tc.monitor = mon
    with sf() as s:
        tokens = {r: create_token(s, r, r) for r in ("reader", "ingest", "admin")}
    return TestClient(app), tokens, notifier, mon


def H(tok):
    return {"Authorization": f"Bearer {tok}"}


def test_auth_required_and_roles(env):
    client, tok, *_ = env
    assert client.get("/healthz").status_code == 200
    assert client.get("/api/v1/services").status_code == 401
    assert client.get("/api/v1/services", headers=H("tc_wrong")).status_code == 401
    assert client.get("/api/v1/services", headers=H(tok["reader"])).status_code == 200
    r = client.post("/api/v1/events", json={"service": "a", "stage": "build", "passed": True}, headers=H(tok["reader"]))
    assert r.status_code == 403
    assert client.post("/api/v1/admin/feed/run", headers=H(tok["ingest"])).status_code == 403


def test_validation_rejects_bad_input_without_reflection(env):
    client, tok, *_ = env
    r = client.post("/api/v1/events", headers=H(tok["ingest"]),
                    json={"service": "../../etc; DROP TABLE", "stage": "build", "passed": True, "extra": "x"})
    assert r.status_code == 422
    assert "DROP TABLE" not in r.text
    r = client.post("/api/v1/sboms", headers=H(tok["ingest"]), json={"service": "a", "sbom": {"bomFormat": "SPDX"}})
    assert r.status_code == 422


def test_body_size_limit(env, monkeypatch):
    client, tok, *_ = env
    import trustchain.server.app as appmod

    r = client.post("/api/v1/events", headers={**H(tok["ingest"]), "content-length": str(appmod.MAX_BODY + 1)},
                    content=b"{}")
    assert r.status_code == 413


def test_ingest_flow_trust_score_and_alert_latency(env):
    client, tok, notifier, _ = env
    rep = {"service": "mnist-api", "repo": "github.com/org/mnist-api", "digest": DIGEST, "passed": False,
           "summary": {"CRITICAL": 1, "HIGH": 0}, "violations": ["CRITICAL 1건"],
           "findings": [{"rule_id": "TC-MODEL-001", "title": "악성 모델", "severity": "CRITICAL", "message": "m",
                         "category": "model"}]}
    assert client.post("/api/v1/reports", json=rep, headers=H(tok["ingest"])).status_code == 201
    t0 = time.perf_counter()
    r = client.post("/api/v1/sboms", json={"service": "mnist-api", "digest": DIGEST, "sbom": SBOM},
                    headers=H(tok["ingest"]))
    elapsed = time.perf_counter() - t0
    assert r.status_code == 201 and r.json()["components"] == 3
    assert r.json()["match"]["alerts"] == 1
    assert elapsed < 60  # SBOM 매칭 후 1분 이내 알림
    assert notifier.sent and notifier.sent[0].component == "pyyaml" and notifier.sent[0].severity == "CRITICAL"

    svc = client.get("/api/v1/services", headers=H(tok["reader"])).json()[0]
    assert svc["name"] == "mnist-api" and svc["components"] == 3 and svc["open_alerts"] == 1
    assert svc["trust_score"] < 50 and svc["last_gate_passed"] is False

    comps = client.get("/api/v1/services/mnist-api/components?q=yaml", headers=H(tok["reader"])).json()
    assert [c["name"] for c in comps] == ["pyyaml"]
    alerts = client.get("/api/v1/alerts", headers=H(tok["reader"])).json()
    assert alerts[0]["vuln_id"] == "PYSEC-TEST-1" and alerts[0]["fixed"] == ["5.4"]

    ev = {"service": "mnist-api", "stage": "deploy", "image": f"ghcr.io/org/mnist-api@{DIGEST}", "passed": True}
    assert client.post("/api/v1/events", json=ev, headers=H(tok["ingest"])).status_code == 201
    events = client.get("/api/v1/events?service=mnist-api", headers=H(tok["reader"])).json()
    assert [e["stage"] for e in events] == ["deploy", "build"]
    blocked = client.get("/api/v1/events?blocked_only=true", headers=H(tok["reader"])).json()
    assert len(blocked) == 1 and blocked[0]["stage"] == "build"


def test_feed_run_once_dedupes(env):
    client, tok, notifier, mon = env
    client.post("/api/v1/sboms", json={"service": "svc", "digest": DIGEST, "sbom": SBOM}, headers=H(tok["ingest"]))
    n_before = len(notifier.sent)
    stats = mon.run_once()
    assert stats.fetched >= 1 and stats.alerts == 0  # 이미 알린 취약점은 중복 알림 없음
    assert len(notifier.sent) == n_before


def test_parse_modified_csv():
    text = "2026-09-02T00:00:00Z,A\n2026-09-01T00:00:00Z,B\n2026-08-01T00:00:00Z,C\n"
    assert parse_modified_csv(text, "2026-09-01T00:00:00Z") == [("2026-09-02T00:00:00Z", "A")]
    assert len(parse_modified_csv(text, None)) == 3


def test_slack_webhook_ssrf_guard():
    with pytest.raises(ValueError):
        SlackNotifier("http://169.254.169.254/latest/meta-data")


def test_assistant_endpoint(env):
    client, tok, *_ = env
    r = client.post("/api/v1/assistant/ask", headers=H(tok["reader"]),
                    json={"question": "pickle 모델 파일을 안전하게 로드하려면 어떻게 해야 하나요?"})
    assert r.status_code == 200
    body = r.json()
    assert body["grounded"] and body["citations"]


def test_safe_filename_normalizes_paths():
    from trustchain.server.uploads import safe_filename

    assert safe_filename("../../etc/sbom.json") == "sbom.json"
    assert safe_filename("C:\\temp\\..\\my sbom (1).json") == "my_sbom__1_.json"
    assert safe_filename("") == "upload"
    assert len(safe_filename("a" * 500 + ".json")) <= 128 and safe_filename("a" * 500 + ".json").endswith(".json")


def test_sbom_file_upload(env, monkeypatch):
    import json

    client, tok, *_ = env
    up = {"file": ("../../etc/sbom.json", json.dumps(SBOM).encode(), "application/json")}
    r = client.post("/api/v1/sboms/upload", data={"service": "upl", "digest": DIGEST}, files=up, headers=H(tok["ingest"]))
    assert r.status_code == 201 and r.json()["components"] == 3 and r.json()["filename"] == "sbom.json"

    bad_ext = {"file": ("sbom.exe", b"{}", "application/octet-stream")}
    assert client.post("/api/v1/sboms/upload", data={"service": "upl"}, files=bad_ext,
                       headers=H(tok["ingest"])).status_code == 415
    not_json = {"file": ("sbom.json", b"\xff\xfe not json", "application/json")}
    assert client.post("/api/v1/sboms/upload", data={"service": "upl"}, files=not_json,
                       headers=H(tok["ingest"])).status_code == 422
    spdx = {"file": ("sbom.json", json.dumps({"bomFormat": "SPDX"}).encode(), "application/json")}
    assert client.post("/api/v1/sboms/upload", data={"service": "upl"}, files=spdx,
                       headers=H(tok["ingest"])).status_code == 422
    assert client.post("/api/v1/sboms/upload", data={"service": "upl"}, files=up,
                       headers=H(tok["reader"])).status_code == 403

    monkeypatch.setenv("TRUSTCHAIN_MAX_UPLOAD", "100")
    big = {"file": ("sbom.json", b" " * 200 + b"{}", "application/json")}
    assert client.post("/api/v1/sboms/upload", data={"service": "upl"}, files=big,
                       headers=H(tok["ingest"])).status_code == 413


def test_unauthenticated_post_rejected_before_body(env):
    # 인증 헤더가 없으면 본문(멀티파트)을 해석하기 전에 401 : 깨진 본문이어도 파싱 오류(400)가 아니라 401
    client, tok, *_ = env
    broken = {"Content-Type": "multipart/form-data; boundary=zzz"}
    assert client.post("/api/v1/sboms/upload", content=b"--zzz\r\nbroken", headers=broken).status_code == 401
    hdr = broken | {"Authorization": "Basic abc"}
    assert client.post("/api/v1/sboms/upload", content=b"--zzz\r\nbroken", headers=hdr).status_code == 401


def test_upload_validation_error_shape(env):
    import json

    client, tok, *_ = env
    spdx = {"file": ("sbom.json", json.dumps({"bomFormat": "SPDX"}).encode(), "application/json")}
    r = client.post("/api/v1/sboms/upload", data={"service": "upl"}, files=spdx, headers=H(tok["ingest"]))
    assert r.status_code == 422 and set(r.json()) == {"detail", "errors"}


def _nvd_item(cid, product, end_excl, alias_of=None):
    return {"cve": {
        "id": cid, "lastModified": "2026-10-01T00:00:00.000",
        "descriptions": [{"lang": "en", "value": f"{product} issue"}],
        "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.1, "baseSeverity": "CRITICAL"}}]},
        "configurations": [{"nodes": [{"cpeMatch": [
            {"vulnerable": True, "criteria": f"cpe:2.3:a:vendor:{product}:*:*:*:*:*:*:*:*",
             "versionEndExcluding": end_excl}]}]}],
    }}


class NVDHTTP(NoNetHTTP):
    """NVD 최근 수정 CVE 응답을 돌려주는 가짜 HTTP."""

    def __init__(self):
        self.urls = []

    def get_json(self, url, **kw):
        self.urls.append(url)
        if "services.nvd.nist.gov" in url and "lastModStartDate" in url:
            return {"totalResults": 3, "vulnerabilities": [
                _nvd_item("CVE-2099-1111", "requests", "2.32.0"),    # SBOM 의 requests 2.31.0 → 영향
                _nvd_item("CVE-2099-2222", "requests", "2.30.0"),    # 2.31.0 은 이미 수정된 버전 → 영향 없음
                _nvd_item("CVE-2020-14343", "pyyaml", "5.4"),        # OSV 에 별칭으로 이미 있음 → OSV 경로가 처리
            ]}
        return super().get_json(url, **kw)


def test_nvd_feed_matches_sbom_components(env, monkeypatch):
    client, tok, notifier, mon = env
    client.post("/api/v1/sboms", json={"service": "svc", "digest": DIGEST, "sbom": SBOM}, headers=H(tok["ingest"]))
    http = NVDHTTP()
    mon.http = http
    monkeypatch.delenv("TRUSTCHAIN_NVD_FEED", raising=False)
    sent_before = {m.vuln_id for m in notifier.sent}
    stats = mon.run_once()
    new = {m.vuln_id for m in notifier.sent} - sent_before
    assert "CVE-2099-1111" in new                      # NVD 에서 수집해 SBOM 과 매칭
    assert "CVE-2099-2222" not in new                  # 버전 범위 밖
    assert "CVE-2020-14343" not in new                 # OSV(PYSEC-TEST-1) 와 중복
    assert stats.nvd_fetched == 3
    nvd_url = next(u for u in http.urls if "lastModStartDate" in u)
    assert "lastModEndDate" in nvd_url and "+" not in nvd_url     # 날짜의 '+' 는 URL 에서 공백으로 해석되어 NVD 가 404 를 낸다
    # 두 번째 실행은 마지막 수집 시각부터 (같은 CVE 로 중복 알림 없음)
    mon.run_once()
    assert [m.vuln_id for m in notifier.sent].count("CVE-2099-1111") == 1


def test_nvd_feed_can_be_disabled(env, monkeypatch):
    _, _, _, mon = env
    http = NVDHTTP()
    mon.http = http
    monkeypatch.setenv("TRUSTCHAIN_NVD_FEED", "0")
    mon.run_once()
    assert not any("lastModStartDate" in u for u in http.urls)


def test_cpe_version_range():
    from trustchain.feed.monitor import cpe_affects

    m = {"criteria": "cpe:2.3:a:python:requests:*:*:*:*:*:*:*:*", "versionStartIncluding": "2.3.0",
         "versionEndExcluding": "2.31.0"}
    assert cpe_affects(m, "requests", "2.30.0") and not cpe_affects(m, "requests", "2.31.0")
    assert not cpe_affects(m, "requests", "2.2.9") and not cpe_affects(m, "urllib3", "2.30.0")
    exact = {"criteria": "cpe:2.3:a:tukaani:xz:5.6.0:*:*:*:*:*:*:*"}
    assert cpe_affects(exact, "xz", "5.6.0") and not cpe_affects(exact, "xz", "5.6.2")
    assert cpe_affects({"criteria": "cpe:2.3:a:x:python_dateutil:*:*:*:*:*:*:*:*", "versionEndIncluding": "2.8"},
                       "python-dateutil", "2.8")
