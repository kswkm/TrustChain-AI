from datetime import timedelta

from conftest import NOW, legit

from trustchain.packages.checker import PackageChecker, verdict_findings
from trustchain.packages.osv import _cvss_base_score, is_affected, parse_vuln
from trustchain.packages.pypi import meta_from_json
from trustchain.packages.requirements import parse_pyproject, parse_requirements
from trustchain.packages.trust_score import compute_trust_score
from trustchain.packages.typosquat import affix_pattern, keyboard_substitution, name_features, osa_distance


def test_parse_requirements(tmp_path):
    (tmp_path / "base.txt").write_text("numpy==1.26.4\n", encoding="utf-8")
    (tmp_path / "requirements.txt").write_text(
        "-r base.txt\n"
        "Requests[socks]==2.31.0 \\\n    --hash=sha256:" + "a" * 64 + "\n"
        "fastapi>=0.110  # comment\n"
        "git+https://github.com/org/lib.git#egg=lib\n"
        "# comment\n--index-url https://pypi.org/simple\n", encoding="utf-8")
    deps = {d.name: d for d in parse_requirements(tmp_path / "requirements.txt")}
    assert set(deps) == {"numpy", "requests", "fastapi", "lib"}
    assert deps["requests"].pinned_version == "2.31.0"
    assert deps["requests"].hashes == ["sha256:" + "a" * 64]
    assert deps["fastapi"].pinned_version is None
    assert deps["lib"].url.startswith("git+")


def test_parse_pyproject(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        '[project]\ndependencies=["httpx>=0.27"]\n[project.optional-dependencies]\ndev=["pytest==8.0"]\n',
        encoding="utf-8")
    names = {d.name for d in parse_pyproject(tmp_path / "pyproject.toml")}
    assert names == {"httpx", "pytest"}


def test_typosquat_features():
    assert osa_distance("reqeusts", "requests") == 1  # 자리바꿈
    assert keyboard_substitution("requesta", "requests")
    assert affix_pattern("python-requests", "requests") is not None
    assert affix_pattern("numpyy", "numpy") == "문자 중복·삽입"
    nf = name_features("reqeusts")
    assert nf.nearest == "requests" and nf.pattern == "문자 자리바꿈"
    assert name_features("requests").is_popular
    nf = name_features("jeIlyfish", raw_name="jeIlyfish", popular=("jellyfish",))
    assert nf.raw_mixed_case_confusable


def make_checker(cfg, fake_pypi):
    return PackageChecker(cfg, fake_pypi, now=NOW)


def test_hallucinated_package_blocked(cfg, fake_pypi):
    v = make_checker(cfg, fake_pypi).check_name("fastapi-security-helperz")
    assert v.verdict == "차단"
    assert any("존재하지 않는" in r for r in v.reasons)
    f = verdict_findings(v)[0]
    assert f.rule_id == "TC-PKG-001" and f.severity.value == "CRITICAL"


def test_typosquat_blocked_and_popular_ok(cfg, fake_pypi):
    ch = make_checker(cfg, fake_pypi)
    bad = ch.check_name("reqeusts")
    assert bad.verdict == "차단"
    assert bad.nearest_popular == "requests"
    assert verdict_findings(bad)[0].rule_id == "TC-PKG-002"
    assert ch.check_name("numpyy").verdict == "차단"
    good = ch.check_name("requests", version="2.31.0")
    assert good.verdict == "정상"
    assert good.trust is not None and good.trust.total >= 60


def test_new_unknown_package_is_warning(cfg, fake_pypi):
    v = make_checker(cfg, fake_pypi).check_name("tiny-new-lib")
    assert v.verdict in ("주의", "차단")
    assert any("최초 등록" in r for r in v.reasons)


def test_import_name_confusion(cfg, fake_pypi):
    v = make_checker(cfg, fake_pypi).check_name("sklearn")
    assert v.verdict != "정상"
    assert any("scikit-learn" in r for r in v.reasons)


def test_allowlist(cfg, fake_pypi):
    cfg.allow_packages = ["internal-lib"]
    assert make_checker(cfg, fake_pypi).check_name("internal-lib").verdict == "정상"


def test_project_import_mismatch(cfg, fake_pypi, tmp_path):
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\nnumpy==1.26.0\n", encoding="utf-8")
    (tmp_path / "app.py").write_text("import requests\nimport yaml\nimport totally_made_up_pkg\nimport os\n",
                                     encoding="utf-8")
    verdicts, findings = make_checker(cfg, fake_pypi).check_project(tmp_path)
    rules = {(f.rule_id, f.message.split("'")[1]) for f in findings}
    assert ("TC-PKG-001", "totally_made_up_pkg") in rules  # 환각 import
    assert ("TC-PKG-003", "yaml") in rules  # 미선언 import
    assert ("TC-PKG-004", "numpy") in rules  # 사용하지 않는 의존성
    assert all(v.verdict == "정상" for v in verdicts)


def test_meta_from_pypi_json():
    data = {
        "info": {"name": "Demo", "version": "1.0", "author": "a", "maintainer_email": "x@y.z, q@w.e",
                 "description": "hello", "project_urls": {"Source": "https://github.com/o/demo"}},
        "releases": {"0.1": [{"upload_time_iso_8601": "2020-01-01T00:00:00.000Z"}],
                     "1.0": [{"upload_time_iso_8601": "2024-01-01T00:00:00.000Z"}]},
        "urls": [{"packagetype": "sdist"}],
    }
    m = meta_from_json("demo", data)
    assert m.exists and m.release_count == 2 and not m.has_wheel
    assert m.repository == "github.com/o/demo"
    assert m.maintainer_count == 3
    assert not meta_from_json("x", {"__status__": 404}).exists


def test_osv_range_matching():
    data = {"affected": [{"package": {"ecosystem": "PyPI", "name": "PyYAML"},
                          "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "5.4"}]}]}]}
    assert is_affected(data, "pyyaml", "5.3.1")
    assert not is_affected(data, "pyyaml", "5.4")
    assert not is_affected(data, "pyyaml", "6.0")
    data2 = {"affected": [{"package": {"ecosystem": "PyPI", "name": "x"}, "versions": ["1.0"],
                           "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "2.0"},
                                                                        {"last_affected": "2.1"}]}]}]}
    assert is_affected(data2, "x", "1.0") and is_affected(data2, "x", "2.1") and not is_affected(data2, "x", "2.2")


def test_cvss_and_parse_vuln():
    assert _cvss_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 9.8
    assert _cvss_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N") == 6.1
    v = parse_vuln({"id": "GHSA-1", "aliases": ["CVE-2020-1"], "severity": [
        {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
        "affected": [{"package": {"name": "a"}, "ranges": [{"events": [{"introduced": "0"}, {"fixed": "1.2"}]}]}]})
    assert v.severity.value == "CRITICAL" and v.fixed_versions == ["1.2"] and v.cve == "CVE-2020-1"


def test_trust_score_components():
    from trustchain.core.findings import Severity
    from trustchain.packages.osv import Vuln

    good = compute_trust_score(legit("a", last_release=None), [], 8.0)
    assert good.total >= 80 and good.grade() == "A"
    stale = legit("b", last_release=NOW - timedelta(days=4000), maintainer_count=1)
    bad = compute_trust_score(stale, [Vuln("X", severity=Severity.CRITICAL)], 2.0)
    assert bad.total < 40
    assert any("취약점" in n for n in bad.notes)


def test_github_client_repo_activity():
    from trustchain.packages.github import GitHubClient

    class FakeHttp:
        def __init__(self):
            self.calls = []

        def get_json(self, url, **kw):
            self.calls.append((url, kw))
            if url.endswith("/gone/repo"):
                return {"__status__": 404}
            return {"archived": True, "pushed_at": "2026-08-01T00:00:00Z", "stargazers_count": 3}

    http = FakeHttp()
    gh = GitHubClient(http, token="ghp_x")
    info = gh.repo_activity("github.com/org/lib")
    assert info.archived is True and info.pushed_at.year == 2026
    assert http.calls[0][0] == "https://api.github.com/repos/org/lib"
    assert http.calls[0][1]["headers"]["Authorization"] == "Bearer ghp_x"
    assert gh.repo_activity("github.com/gone/repo") is None and gh.repo_activity(None) is None


def test_trust_score_uses_github_activity():
    from datetime import timedelta

    from trustchain.packages.github import RepoActivity

    stale = legit("a", last_release=NOW - timedelta(days=1500))
    base = compute_trust_score(stale, [], 5.0, now=NOW)
    active = compute_trust_score(stale, [], 5.0, repo=RepoActivity(False, NOW - timedelta(days=10)), now=NOW)
    archived = compute_trust_score(stale, [], 5.0, repo=RepoActivity(True, NOW - timedelta(days=10)), now=NOW)
    assert active.maintenance > base.maintenance                    # 저장소는 최근까지 활동 (배포만 오래됨)
    assert archived.maintenance < base.maintenance and any("보관" in n for n in archived.notes)
