"""F8. Verify Gate : 배포 전 서명·출처 증명 검증.

검증 항목 (모두 통과해야 배포)
1. 이미지가 digest(@sha256:...)로 지정되었는가 — 태그는 바꿔치기 가능
2. cosign keyless 서명 : Fulcio 인증서의 OIDC 발급자와 서명 주체(빌드 워크플로우) 일치
3. 서명 인증서의 저장소·브랜치 클레임 일치
4. SLSA Provenance : slsa-verifier 로 빌더 ID·소스 저장소·브랜치 검증
5. SBOM(CycloneDX)·AI-BOM 증명(attestation) 첨부 여부
"""

from __future__ import annotations

import base64
import json
import re
import shutil
import subprocess  # nosec - 고정 인자 리스트, 셸 미사용
from dataclasses import dataclass, field
from typing import Any, Callable

from trustchain.core.config import ProvenancePolicy

DIGEST_REF = re.compile(r"^[a-z0-9.\-]+(?::\d+)?/[a-z0-9._\-/]+@sha256:[0-9a-f]{64}$")
AIBOM_PREDICATE = "https://trustchain.dev/attestations/aibom/v1"

Runner = Callable[[list[str]], tuple[int, str, str]]


def _default_runner(cmd: list[str]) -> tuple[int, str, str]:
    exe = shutil.which(cmd[0])
    if not exe:
        return 127, "", f"{cmd[0]} 가 설치되어 있지 않습니다"
    try:
        r = subprocess.run([exe, *cmd[1:]], capture_output=True, text=True, timeout=300, check=False)  # nosec
    except (OSError, subprocess.TimeoutExpired) as e:
        return 1, "", e.__class__.__name__
    return r.returncode, r.stdout, r.stderr


@dataclass
class Check:
    name: str
    passed: bool
    detail: str = ""


@dataclass
class GateResult:
    image: str
    checks: list[Check] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return bool(self.checks) and all(c.passed for c in self.checks)

    def to_dict(self) -> dict[str, Any]:
        return {"image": self.image, "passed": self.passed,
                "checks": [{"name": c.name, "passed": c.passed, "detail": c.detail} for c in self.checks]}


def identity_regexp(policy: ProvenancePolicy) -> str:
    """Fulcio 인증서 SAN (재사용 워크플로우의 job_workflow_ref) 정규식."""
    repo = (policy.signer_repo or policy.source_repo).removeprefix("github.com/")
    wf = policy.workflow_path or ".github/workflows/"
    wf_re = re.escape(wf) + ("[^@]+" if wf.endswith("/") else "")
    return f"^https://github\\.com/{re.escape(repo)}/{wf_re}@refs/(heads|tags)/.+$"


def check_signature_claims(entries: list[dict[str, Any]], policy: ProvenancePolicy) -> Check:
    """cosign verify --output json 결과의 인증서 클레임 확인."""
    if not entries:
        return Check("서명 클레임", False, "검증된 서명이 없습니다")
    want_repo = policy.source_repo.removeprefix("github.com/")
    for e in entries:
        opt = e.get("optional") or {}
        repo = opt.get("githubWorkflowRepository") or opt.get("sourceRepositoryURI", "").removeprefix(
            "https://github.com/")
        ref = opt.get("githubWorkflowRef") or opt.get("sourceRepositoryRef") or ""
        issuer = opt.get("Issuer") or opt.get("issuer")
        if issuer and issuer != policy.oidc_issuer:
            continue
        if want_repo and repo and repo != want_repo:
            continue
        if policy.branch and ref and ref not in (f"refs/heads/{policy.branch}",) and not ref.startswith("refs/tags/"):
            continue
        return Check("서명 클레임", True, f"repo={repo or '?'} ref={ref or '?'} issuer={issuer or '?'}")
    return Check("서명 클레임", False, "서명 인증서의 저장소/브랜치/발급자가 정책과 일치하지 않습니다")


def decode_dsse_statements(output: str) -> list[dict[str, Any]]:
    """cosign verify-attestation 출력(줄 단위 DSSE envelope JSON) → in-toto statement 목록."""
    out = []
    for line in output.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            env = json.loads(line)
            payload = base64.b64decode(env.get("payload", ""))
            out.append(json.loads(payload))
        except (ValueError, TypeError):
            continue
    return out


def check_provenance_statement(stmt: dict[str, Any], policy: ProvenancePolicy, digest: str | None = None) -> Check:
    """SLSA v1.0 / v0.2 predicate 의 빌더·소스·브랜치·대상 digest 검증 (slsa-verifier 보조)."""
    ptype = stmt.get("predicateType", "")
    pred = stmt.get("predicate") or {}
    if digest:
        subjects = [s.get("digest", {}).get("sha256") for s in stmt.get("subject", [])]
        if digest.removeprefix("sha256:") not in subjects:
            return Check("SLSA 출처 증명", False, "증명의 subject digest 가 배포 이미지와 다릅니다")
    if ptype.startswith("https://slsa.dev/provenance/v1"):
        builder = ((pred.get("runDetails") or {}).get("builder") or {}).get("id", "")
        ext = ((pred.get("buildDefinition") or {}).get("externalParameters") or {})
        wf = ext.get("workflow") or {}
        repo = (wf.get("repository") or "").removeprefix("https://")
        ref = wf.get("ref", "")
    elif ptype.startswith("https://slsa.dev/provenance/v0.2"):
        builder = (pred.get("builder") or {}).get("id", "")
        inv = (pred.get("invocation") or {}).get("configSource") or {}
        repo = re.sub(r"^git\+https://", "", inv.get("uri", "")).split("@")[0]
        ref = inv.get("uri", "").split("@", 1)[1] if "@" in inv.get("uri", "") else ""
    else:
        return Check("SLSA 출처 증명", False, f"지원하지 않는 predicateType: {ptype or '없음'}")
    problems = []
    if policy.builder_id and not builder.startswith(policy.builder_id):
        problems.append(f"빌더 불일치({builder})")
    if policy.source_repo and repo != policy.source_repo:
        problems.append(f"소스 저장소 불일치({repo})")
    if policy.branch and ref and ref != f"refs/heads/{policy.branch}" and not ref.startswith("refs/tags/"):
        problems.append(f"브랜치 불일치({ref})")
    if problems:
        return Check("SLSA 출처 증명", False, ", ".join(problems))
    return Check("SLSA 출처 증명", True, f"builder={builder} repo={repo} ref={ref}")


class VerifyGate:
    def __init__(self, policy: ProvenancePolicy, runner: Runner | None = None,
                 require_sbom: bool = True, require_aibom: bool = False):
        self.policy = policy
        self.run = runner or _default_runner
        self.require_sbom = require_sbom
        self.require_aibom = require_aibom

    def _cosign_base(self) -> list[str]:
        return ["--certificate-identity-regexp", identity_regexp(self.policy),
                "--certificate-oidc-issuer", self.policy.oidc_issuer]

    def verify(self, image: str) -> GateResult:
        res = GateResult(image)
        if not DIGEST_REF.match(image):
            res.checks.append(Check("digest 지정", False, "이미지는 registry/repo@sha256:<digest> 형식이어야 합니다"))
            return res
        res.checks.append(Check("digest 지정", True))
        digest = image.split("@", 1)[1]

        # 2~3. 서명
        code, out, err = self.run(["cosign", "verify", image, *self._cosign_base(), "--output", "json"])
        if code != 0:
            res.checks.append(Check("cosign 서명", False, (err or out).strip()[-300:] or f"exit {code}"))
        else:
            res.checks.append(Check("cosign 서명", True, "Fulcio 인증서·Rekor 투명성 로그 검증 통과"))
            try:
                entries = json.loads(out)
            except ValueError:
                entries = []
            res.checks.append(check_signature_claims(entries if isinstance(entries, list) else [], self.policy))

        # 4. SLSA provenance (slsa-verifier)
        cmd = ["slsa-verifier", "verify-image", image, "--source-uri", self.policy.source_repo,
               "--builder-id", self.policy.builder_id]
        if self.policy.branch:
            cmd += ["--source-branch", self.policy.branch]
        code, out, err = self.run(cmd)
        res.checks.append(Check("SLSA 출처 증명", code == 0,
                                "slsa-verifier PASSED" if code == 0 else (err or out).strip()[-300:]))

        # 5. SBOM / AI-BOM 증명
        if self.require_sbom:
            code, out, err = self.run(["cosign", "verify-attestation", image, "--type", "cyclonedx",
                                       *self._cosign_base()])
            stmts = decode_dsse_statements(out) if code == 0 else []
            ok = code == 0 and any(digest.removeprefix("sha256:") in [s.get("digest", {}).get("sha256") for s in
                                                                      st.get("subject", [])] for st in stmts)
            res.checks.append(Check("SBOM 증명 첨부", ok, "CycloneDX SBOM 증명 확인" if ok else
                                    ((err or out).strip()[-300:] or "SBOM 증명 없음")))
        if self.require_aibom:
            code, out, err = self.run(["cosign", "verify-attestation", image, "--type", AIBOM_PREDICATE,
                                       *self._cosign_base()])
            res.checks.append(Check("AI-BOM 증명 첨부", code == 0,
                                    "AI-BOM 증명 확인" if code == 0 else (err or out).strip()[-300:]))
        return res
