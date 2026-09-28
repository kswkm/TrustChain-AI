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
