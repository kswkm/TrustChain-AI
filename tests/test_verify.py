import base64
import json
import re

from trustchain.attest.verify import VerifyGate, check_provenance_statement, decode_dsse_statements, identity_regexp
from trustchain.core.config import ProvenancePolicy

DIGEST = "sha256:" + "c" * 64
IMAGE = f"ghcr.io/org/mnist-api@{DIGEST}"


def policy() -> ProvenancePolicy:
    return ProvenancePolicy(source_repo="github.com/org/mnist-api", branch="main",
                            workflow_path=".github/workflows/trustchain-ci.yml")


def dsse(stmt: dict) -> str:
    return json.dumps({"payloadType": "application/vnd.in-toto+json",
                       "payload": base64.b64encode(json.dumps(stmt).encode()).decode(), "signatures": []})


class FakeRunner:
    def __init__(self, fail: set[str] | None = None, repo: str = "org/mnist-api"):
        self.fail = fail or set()
        self.repo = repo
        self.calls: list[list[str]] = []

    def __call__(self, cmd: list[str]) -> tuple[int, str, str]:
        self.calls.append(cmd)
        key = cmd[0] + ":" + cmd[1]
        if key in self.fail:
            return 1, "", f"{key} failed: no matching signatures"
        if key == "cosign:verify":
            return 0, json.dumps([{"optional": {"Issuer": "https://token.actions.githubusercontent.com",
                                                "githubWorkflowRepository": self.repo,
                                                "githubWorkflowRef": "refs/heads/main"}}]), ""
        if key == "cosign:verify-attestation":
            return 0, dsse({"_type": "https://in-toto.io/Statement/v1", "predicateType": "https://cyclonedx.org/bom",
                            "subject": [{"name": "img", "digest": {"sha256": "c" * 64}}], "predicate": {}}) + "\n", ""
        return 0, "PASSED: SLSA verification passed", ""


def test_identity_regexp():
    rx = identity_regexp(policy())
    assert re.match(rx, "https://github.com/org/mnist-api/.github/workflows/trustchain-ci.yml@refs/heads/main")
    assert not re.match(rx, "https://github.com/evil/mnist-api/.github/workflows/trustchain-ci.yml@refs/heads/main")


def test_gate_passes_with_all_checks():
    runner = FakeRunner()
    res = VerifyGate(policy(), runner=runner).verify(IMAGE)
    assert res.passed, res.to_dict()
    assert [c.name for c in res.checks] == ["digest 지정", "cosign 서명", "서명 클레임", "SLSA 출처 증명", "SBOM 증명 첨부"]
    slsa = next(c for c in runner.calls if c[0] == "slsa-verifier")
    assert "--source-uri" in slsa and "github.com/org/mnist-api" in slsa and "--source-branch" in slsa


def test_gate_rejects_tag_reference():
    res = VerifyGate(policy(), runner=FakeRunner()).verify("ghcr.io/org/mnist-api:latest")
    assert not res.passed and res.checks[0].name == "digest 지정"


def test_gate_rejects_unsigned_image():
    res = VerifyGate(policy(), runner=FakeRunner(fail={"cosign:verify"})).verify(IMAGE)
    assert not res.passed
    assert not next(c for c in res.checks if c.name == "cosign 서명").passed


def test_gate_rejects_wrong_repo_claim_and_missing_provenance():
    res = VerifyGate(policy(), runner=FakeRunner(repo="attacker/fork")).verify(IMAGE)
    assert not next(c for c in res.checks if c.name == "서명 클레임").passed
    res = VerifyGate(policy(), runner=FakeRunner(fail={"slsa-verifier:verify-image"})).verify(IMAGE)
    assert not res.passed


def test_provenance_statement_v1():
    stmt = {"predicateType": "https://slsa.dev/provenance/v1", "subject": [{"digest": {"sha256": "c" * 64}}],
            "predicate": {"runDetails": {"builder": {"id": policy().builder_id + "@refs/tags/v2.1.0"}},
                          "buildDefinition": {"externalParameters": {"workflow": {
                              "repository": "https://github.com/org/mnist-api", "ref": "refs/heads/main"}}}}}
    assert check_provenance_statement(stmt, policy(), DIGEST).passed
    stmt["predicate"]["buildDefinition"]["externalParameters"]["workflow"]["ref"] = "refs/heads/dev"
    assert not check_provenance_statement(stmt, policy(), DIGEST).passed
    assert not check_provenance_statement(stmt, policy(), "sha256:" + "d" * 64).passed
    assert len(decode_dsse_statements(dsse(stmt) + "\nnot json\n")) == 1
