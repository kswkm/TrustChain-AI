"""F6. AI-BOM : CycloneDX machine-learning-model / data 구성요소.

모델 정보는 프로젝트의 `models.toml` 에 선언한다.

    [[model]]
    name = "mnist-cnn"
    version = "1.0.0"
    path = "model/mnist.keras"
    framework = "tensorflow-keras"
    task = "image-classification"
    source_repo = "https://github.com/org/repo"
    revision = "<commit sha>"
    license = "Apache-2.0"

    [[model.dataset]]
    name = "MNIST"
    url = "https://storage.googleapis.com/tensorflow/tf-keras-datasets/mnist.npz"
    sha256 = "<데이터셋 파일 해시>"

선언되지 않은 모델 파일도 해시와 함께 기록하되 '출처 미기재'로 표시한다.
배포 시 verify_aibom 으로 실제 가중치 해시와 AI-BOM 을 대조한다.
"""

from __future__ import annotations

import hashlib
import json
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from trustchain.bom.sbom import empty_bom
from trustchain.core.files import iter_files, rel
from trustchain.core.findings import Finding, Severity
from trustchain.scan.modelscan import MODEL_SUFFIXES, scan_model_file

PROP_PATH = "trustchain:path"
PROP_FORMAT = "trustchain:format"
PROP_DECLARED = "trustchain:declared"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _format_of(path: Path) -> str:
    return {
        ".keras": "keras-v3", ".h5": "keras-hdf5", ".safetensors": "safetensors", ".onnx": "onnx", ".pt": "pytorch",
        ".pth": "pytorch", ".bin": "pytorch-bin", ".pkl": "pickle", ".joblib": "joblib", ".gguf": "gguf",
        ".npz": "numpy", ".npy": "numpy",
    }.get(path.suffix.lower(), path.suffix.lower().lstrip("."))


def load_model_declarations(root: Path) -> list[dict[str, Any]]:
    for cand in (root / "models.toml", root / "model" / "models.toml", root / "models" / "models.toml"):
        if cand.is_file():
            return tomllib.loads(cand.read_text(encoding="utf-8")).get("model", [])
    return []


def model_component(decl: dict[str, Any], file_path: Path | None, root: Path) -> tuple[dict[str, Any], list[dict]]:
    name = decl.get("name") or (file_path.stem if file_path else "unknown-model")
    version = str(decl.get("version", "0.0.0"))
    ref = f"model:{name}@{version}"
    comp: dict[str, Any] = {
        "type": "machine-learning-model", "bom-ref": ref, "name": name, "version": version,
        "properties": [{"name": PROP_DECLARED, "value": "true" if decl.get("_declared", True) else "false"}],
    }
    if decl.get("license"):
        comp["licenses"] = [{"license": {"id": decl["license"]}}]
    if file_path is not None and file_path.is_file():
        comp["hashes"] = [{"alg": "SHA-256", "content": sha256_file(file_path)}]
        comp["properties"] += [
            {"name": PROP_PATH, "value": rel(file_path, root)},
            {"name": PROP_FORMAT, "value": _format_of(file_path)},
        ]
    elif decl.get("sha256"):
        # 실행 시 내려받는 원격 모델(예: HuggingFace) : 리비전으로 고정한 가중치 파일의 해시를 선언값으로 기록
        comp["hashes"] = [{"alg": "SHA-256", "content": str(decl["sha256"]).lower()}]
        comp["properties"].append({"name": "trustchain:remote", "value": "true"})
        if decl.get("file"):
            comp["properties"].append({"name": PROP_FORMAT, "value": _format_of(Path(str(decl["file"])))})
    ext = []
    if decl.get("source_repo"):
        ext.append({"type": "vcs", "url": decl["source_repo"],
                    **({"comment": f"revision {decl['revision']}"} if decl.get("revision") else {})})
    if decl.get("model_card_url"):
        ext.append({"type": "documentation", "url": decl["model_card_url"]})
    if ext:
        comp["externalReferences"] = ext
    if decl.get("revision"):
        comp["properties"].append({"name": "trustchain:revision", "value": str(decl["revision"])})
    datasets = []
    ds_components = []
    for ds in decl.get("dataset", []) or []:
        dref = f"data:{ds.get('name')}"
        datasets.append({"ref": dref})
        dc: dict[str, Any] = {
            "type": "data", "bom-ref": dref, "name": ds.get("name", "dataset"),
            "data": [{"type": "dataset", "name": ds.get("name", "dataset"),
                      **({"contents": {"url": ds["url"]}} if ds.get("url") else {}),
                      **({"description": ds["description"]} if ds.get("description") else {})}],
        }
        if ds.get("sha256"):
            dc["hashes"] = [{"alg": "SHA-256", "content": ds["sha256"]}]
        if ds.get("license"):
            dc["licenses"] = [{"license": {"id": ds["license"]}}]
        ds_components.append(dc)
    params: dict[str, Any] = {}
    if decl.get("task"):
        params["task"] = decl["task"]
    if decl.get("framework"):
        params["architectureFamily"] = decl["framework"]
    if datasets:
        params["datasets"] = datasets
    if params:
        comp["modelCard"] = {"modelParameters": params}
    return comp, ds_components


def generate_aibom(root: Path, model_dirs: list[str], exclude: list[str], app_name: str = "app") -> dict[str, Any]:
    root = Path(root)
    bom = empty_bom(app_name)
    decls = load_model_declarations(root)
    declared_paths: set[Path] = set()
    comps: list[dict[str, Any]] = []
    for d in decls:
        fp = (root / d["path"]).resolve() if d.get("path") else None
        if fp is not None and not fp.is_relative_to(root.resolve()):
            raise ValueError(f"모델 경로가 프로젝트 밖을 가리킵니다: {d['path']}")
        if fp:
            declared_paths.add(fp)
        c, ds = model_component({**d, "_declared": True}, fp, root)
        comps.append(c)
        comps.extend(ds)
    for md in model_dirs:
        base = root / md
        if not base.is_dir():
            continue
        for p in iter_files(base, MODEL_SUFFIXES, exclude):
            if p.resolve() in declared_paths:
                continue
            c, _ = model_component({"name": p.stem, "_declared": False}, p, root)
            comps.append(c)
    bom["components"] = comps
    return bom


def merge_boms(sbom: dict[str, Any], aibom: dict[str, Any]) -> dict[str, Any]:
    refs = {c.get("bom-ref") for c in sbom.get("components", [])}
    merged = dict(sbom)
    merged["components"] = list(sbom.get("components", [])) + [
        c for c in aibom.get("components", []) if c.get("bom-ref") not in refs
    ]
    return merged


def _prop(c: dict[str, Any], name: str) -> str | None:
    return next((p["value"] for p in c.get("properties", []) if p.get("name") == name), None)


@dataclass
class ModelCheck:
    name: str
    path: str | None
    expected: str | None
    actual: str | None
    ok: bool
    reason: str = ""


def verify_aibom(aibom: dict[str, Any], root: Path, scan: bool = True) -> list[ModelCheck]:
    """AI-BOM 의 가중치 해시와 실제 파일을 대조 (배포 전/서비스 시작 시)."""
    root = Path(root).resolve()
    out: list[ModelCheck] = []
    for c in aibom.get("components", []):
        if c.get("type") != "machine-learning-model":
            continue
        path = _prop(c, PROP_PATH)
        expected = next((h["content"] for h in c.get("hashes", []) if h.get("alg") == "SHA-256"), None)
        if _prop(c, "trustchain:remote") == "true":
            # 실행 시 내려받는 원격 모델 : 리비전(커밋)과 가중치 해시가 모두 고정되어 있어야 통과
            rev = _prop(c, "trustchain:revision") or ""
            pinned = bool(expected) and len(rev) == 40 and all(ch in "0123456789abcdef" for ch in rev)
            out.append(ModelCheck(c.get("name", "?"), None, expected, None, pinned,
                                  f"원격 모델 (리비전 {rev[:12]} 고정)" if pinned else "원격 모델의 리비전·해시가 고정되지 않음"))
            continue
        if not path or not expected:
            out.append(ModelCheck(c.get("name", "?"), path, expected, None, False, "AI-BOM 에 경로/해시 정보 없음"))
            continue
        fp = (root / path).resolve()
        if not fp.is_relative_to(root) or not fp.is_file():
            out.append(ModelCheck(c["name"], path, expected, None, False, "모델 파일 없음"))
            continue
        actual = sha256_file(fp)
        ok = actual == expected
        reason = "" if ok else "가중치 해시 불일치 (모델이 변경됨)"
        if ok and scan:
            r = scan_model_file(fp)
            if r.dangerous:
                ok, reason = False, "모델 파일에 위험 호출 포함"
        if ok and _prop(c, PROP_DECLARED) == "false":
            reason = "출처 미기재 모델 (models.toml 에 선언 필요)"
        out.append(ModelCheck(c["name"], path, expected, actual, ok, reason))
    return out


def aibom_findings(aibom: dict[str, Any]) -> list[Finding]:
    out = []
    for c in aibom.get("components", []):
        if c.get("type") == "machine-learning-model" and _prop(c, PROP_DECLARED) == "false":
            out.append(Finding(
                rule_id="TC-AIBOM-001", title="출처가 기록되지 않은 AI 모델", severity=Severity.MEDIUM, category="model",
                file=_prop(c, PROP_PATH), message=f"모델 '{c['name']}' 의 원본 저장소·리비전·학습 데이터 출처가 없습니다.",
                fix="models.toml 에 source_repo, revision, dataset 정보를 선언하세요.",
            ))
    return out


def load_bom(path: Path) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))
