import collections
import io
import json
import os
import pickle
import struct
import zipfile

from trustchain.bom.aibom import generate_aibom, merge_boms, verify_aibom
from trustchain.bom.sbom import components_from_sbom, parse_purl, sbom_from_project
from trustchain.iac.k8s import check_manifest
from trustchain.scan.image import check_dockerfiles, parse_trivy
from trustchain.scan.modelscan import classify_global, pickle_globals, scan_model_file, scan_models


class Evil:
    def __reduce__(self):
        return (os.system, ("echo pwned",))


class EvilExec:
    def __reduce__(self):
        return (exec, ("print(1)",))


def test_pickle_globals_all_protocols():
    for proto in range(0, pickle.HIGHEST_PROTOCOL + 1):
        gl, _ = pickle_globals(pickle.dumps(Evil(), protocol=proto))
        assert any(g.endswith(".system") for g in gl), proto
        assert classify_global(gl[0]) == "dangerous"
    gl, _ = pickle_globals(pickle.dumps(EvilExec(), protocol=4))
    assert "builtins.exec" in gl


def test_benign_pickle_is_safe(tmp_path):
    p = tmp_path / "ok.pkl"
    p.write_bytes(pickle.dumps(collections.OrderedDict(a=[1, 2]), protocol=4))
    r = scan_model_file(p)
    assert r.safe and not r.dangerous and not r.unknown


def test_torch_style_zip_with_evil_data_pkl(tmp_path):
    p = tmp_path / "model.pt"
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("archive/data.pkl", pickle.dumps(Evil(), protocol=2))
        z.writestr("archive/version", "3")
    r = scan_model_file(p)
    assert r.dangerous


def test_appended_second_pickle_is_scanned(tmp_path):
    p = tmp_path / "two.pkl"
    p.write_bytes(pickle.dumps({"w": 1}, protocol=4) + pickle.dumps(Evil(), protocol=4))
    assert scan_model_file(p).dangerous


def test_keras_lambda_and_safetensors_and_npy(tmp_path):
    k = tmp_path / "m.keras"
    with zipfile.ZipFile(k, "w") as z:
        z.writestr("config.json", json.dumps({"config": {"layers": [{"class_name": "Lambda"}]}}))
    assert "keras.layers.Lambda" in scan_model_file(k).dangerous

    st = tmp_path / "w.safetensors"
    header = json.dumps({"w": {"dtype": "F32", "shape": [1], "data_offsets": [0, 4]}}).encode()
    st.write_bytes(struct.pack("<Q", len(header)) + header + b"\0\0\0\0")
    assert scan_model_file(st).safe
    bad = tmp_path / "bad.safetensors"
    bad.write_bytes(struct.pack("<Q", 5) + b"{oops")
    assert scan_model_file(bad).issues

    import numpy as np

    buf = io.BytesIO()
    np.save(buf, np.array([{"a": 1}], dtype=object), allow_pickle=True)
    npy = tmp_path / "o.npy"
    npy.write_bytes(buf.getvalue())
    assert scan_model_file(npy).issues


def test_scan_models_findings(tmp_path):
    (tmp_path / "models").mkdir()
    (tmp_path / "models" / "evil.pkl").write_bytes(pickle.dumps(Evil()))
    (tmp_path / "models" / "plain.pkl").write_bytes(pickle.dumps([1, 2, 3]))
    _, findings = scan_models(tmp_path, [], tmp_path)
    by = {f.file: f.rule_id for f in findings}
    assert by["models/evil.pkl"] == "TC-MODEL-001"
    assert by["models/plain.pkl"] == "TC-MODEL-004"


def test_sbom_from_project_and_components(tmp_path):
    (tmp_path / "requirements.txt").write_text("Requests==2.31.0\nnumpy>=1.0\n", encoding="utf-8")
    bom = sbom_from_project(tmp_path, "demo", "1.0")
    assert bom["bomFormat"] == "CycloneDX" and bom["specVersion"] == "1.6"
    comps = components_from_sbom(bom)
    assert {"name": "requests", "version": "2.31.0", "purl": "pkg:pypi/requests@2.31.0", "ecosystem": "PyPI",
            "type": "library", "sha256": None} in comps
    assert parse_purl("pkg:deb/debian/openssl@3.0.11-1?arch=amd64")["name"] == "openssl"
    assert parse_purl("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1")["namespace"] == \
        "org.apache.logging.log4j"


def test_aibom_generate_and_verify_tamper(tmp_path):
    (tmp_path / "model").mkdir()
    m = tmp_path / "model" / "mnist.keras"
    with zipfile.ZipFile(m, "w") as z:
        z.writestr("config.json", "{}")
    (tmp_path / "model" / "extra.onnx").write_bytes(b"onnx")
    (tmp_path / "models.toml").write_text(
        '[[model]]\nname="mnist-cnn"\nversion="1.0.0"\npath="model/mnist.keras"\nframework="tensorflow-keras"\n'
        'source_repo="https://github.com/org/repo"\nrevision="abc123"\n'
        '[[model.dataset]]\nname="MNIST"\nurl="https://example.org/mnist.npz"\nsha256="' + "1" * 64 + '"\n',
        encoding="utf-8")
    aibom = generate_aibom(tmp_path, ["model"], [], "demo")
    types = [c["type"] for c in aibom["components"]]
    assert types.count("machine-learning-model") == 2 and "data" in types
    mnist = next(c for c in aibom["components"] if c["name"] == "mnist-cnn")
    assert mnist["modelCard"]["modelParameters"]["datasets"] == [{"ref": "data:MNIST"}]
    checks = {c.name: c for c in verify_aibom(aibom, tmp_path)}
    assert checks["mnist-cnn"].ok
    assert checks["extra"].ok and "출처 미기재" in checks["extra"].reason
    # 모델 교체(변조) → 해시 불일치
    with zipfile.ZipFile(m, "w") as z:
        z.writestr("config.json", '{"changed": true}')
    assert not {c.name: c for c in verify_aibom(aibom, tmp_path)}["mnist-cnn"].ok
    merged = merge_boms({"components": [{"bom-ref": "x"}]}, aibom)
    assert len(merged["components"]) == 1 + len(aibom["components"])


def test_dockerfile_checks(tmp_path):
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.11-slim AS build\nRUN curl -sSL https://x.sh | sh\nFROM build\nENV API_TOKEN=abc\n",
        encoding="utf-8")
    rules = {f.rule_id for f in check_dockerfiles(tmp_path, [])}
    assert {"TC-IMG-001", "TC-IMG-003", "TC-IMG-004", "TC-IMG-005"} <= rules
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.11-slim@sha256:" + "a" * 64 + "\nUSER 10001\n", encoding="utf-8")
    assert check_dockerfiles(tmp_path, []) == []


def test_trivy_parse():
    data = {"Results": [{"Target": "debian", "Class": "os-pkgs", "Vulnerabilities": [
        {"VulnerabilityID": "CVE-2024-1", "PkgName": "openssl", "InstalledVersion": "3.0.1", "FixedVersion": "3.0.2",
         "Severity": "CRITICAL", "Title": "bad"}]}]}
    f = parse_trivy(data, "img")[0]
    assert f.severity.value == "CRITICAL" and "3.0.2" in f.fix and f.category == "image"


def test_k8s_manifest_checks():
    doc = {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "x"}, "spec": {"template": {"spec": {
        "hostNetwork": True,
        "containers": [{"name": "c", "image": "nginx:latest", "securityContext": {"privileged": True},
                        "env": [{"name": "DB_PASSWORD", "value": "x"}]}]}}}}
    rules = {f.rule_id for f in check_manifest(doc, "d.yaml")}
    assert {"TC-K8S-001", "TC-K8S-004", "TC-K8S-005", "TC-K8S-007", "TC-K8S-011"} <= rules
    hardened = {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "p"}, "spec": {
        "serviceAccountName": "app", "automountServiceAccountToken": False,
        "securityContext": {"runAsNonRoot": True},
        "containers": [{"name": "c", "image": "ghcr.io/o/a@sha256:" + "b" * 64,
                        "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                            "capabilities": {"drop": ["ALL"]}},
                        "resources": {"limits": {"memory": "256Mi", "cpu": "500m"}}}]}}
    assert check_manifest(hardened, "p.yaml") == []


def test_image_gate_ignores_unfixed_by_default(tmp_path):
    from trustchain.core.config import Config
    from trustchain.scan.gate import run_gate

    data = {"Results": [{"Target": "debian", "Vulnerabilities": [
        {"VulnerabilityID": "CVE-2023-45853", "PkgName": "zlib1g", "InstalledVersion": "1:1.2.13", "Severity": "CRITICAL"}]}]}
    rep = tmp_path / "t.json"
    rep.write_text(json.dumps(data), encoding="utf-8")
    cfg = Config(root=tmp_path)
    out = run_gate(cfg, stages={"image"}, trivy_report=rep, external_tools=False)
    assert out.passed and out.report.counts()["CRITICAL"] == 1  # 보고는 하되 차단하지 않음
    cfg.gate.ignore_unfixed = False
    assert not run_gate(cfg, stages={"image"}, trivy_report=rep, external_tools=False).passed


def test_image_gate_blocks_end_of_support_os(tmp_path):
    # 지원이 끝난 OS(EOSL) 는 앞으로도 패치가 나오지 않으므로 '패치 없음 무시' 정책과 관계없이 차단한다
    from trustchain.core.config import Config
    from trustchain.scan.gate import run_gate

    vulns = [{"VulnerabilityID": "CVE-2023-45853", "PkgName": "zlib1g", "InstalledVersion": "1:1.2.11", "Severity": "CRITICAL"}]
    eosl = {"Metadata": {"OS": {"Family": "debian", "Name": "10.13", "EOSL": True}},
            "Results": [{"Target": "debian 10.13", "Vulnerabilities": vulns}]}
    rep = tmp_path / "t.json"
    rep.write_text(json.dumps(eosl), encoding="utf-8")
    out = run_gate(Config(root=tmp_path), stages={"image"}, trivy_report=rep, external_tools=False)
    assert not out.passed
    f = next(f for f in out.report.findings if f.rule_id == "TC-IMG-006")
    assert f.severity.value == "CRITICAL" and "debian 10.13" in f.message


def test_aibom_records_remote_pinned_model(tmp_path):
    from trustchain.bom.aibom import generate_aibom

    (tmp_path / "models.toml").write_text(
        '[[model]]\nname = "intfloat/multilingual-e5-small"\nversion = "614241f6"\nframework = "sentence-transformers"\n'
        'source_repo = "https://huggingface.co/intfloat/multilingual-e5-small"\n'
        'revision = "614241f622f53c4eeff9890bdc4f31cfecc418b3"\n'
        'sha256 = "1a55775f53449dac10a2bcbc312469fac40b96d53198c407081a831f81c98477"\nfile = "model.safetensors"\n',
        encoding="utf-8")
    bom = generate_aibom(tmp_path, [], [], "platform")
    comp = next(c for c in bom["components"] if c["name"] == "intfloat/multilingual-e5-small")
    assert comp["hashes"] == [{"alg": "SHA-256", "content": "1a55775f53449dac10a2bcbc312469fac40b96d53198c407081a831f81c98477"}]
    props = {p["name"]: p["value"] for p in comp["properties"]}
    assert props["trustchain:revision"] == "614241f622f53c4eeff9890bdc4f31cfecc418b3" and props["trustchain:remote"] == "true"


def test_aibom_verify_remote_model_requires_pinning(tmp_path):
    from trustchain.bom.aibom import verify_aibom

    def comp(props):
        return {"type": "machine-learning-model", "name": "m", "hashes": [{"alg": "SHA-256", "content": "ab" * 32}],
                "properties": [{"name": k, "value": v} for k, v in props.items()]}

    pinned = comp({"trustchain:remote": "true", "trustchain:revision": "614241f622f53c4eeff9890bdc4f31cfecc418b3"})
    unpinned = comp({"trustchain:remote": "true"})
    checks = verify_aibom({"components": [pinned, unpinned]}, tmp_path)
    assert [c.ok for c in checks] == [True, False]
    assert "리비전" in checks[1].reason
