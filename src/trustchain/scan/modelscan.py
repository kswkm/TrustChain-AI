"""F5. AI 모델 파일 스캐너 (악성 pickle 탐지).

모델을 '불러오지 않고' pickle opcode 를 정적으로 분석한다. pickle 은 로드 시점에
GLOBAL/STACK_GLOBAL 로 가져온 임의의 호출 가능 객체를 REDUCE 로 실행하므로,
참조하는 전역(모듈.이름)을 추출해 위험 목록·허용 목록과 비교한다.

지원 형식
- .pkl .pickle .joblib(비압축·zlib) .dat : 원시 pickle
- .pt .pth .ckpt .bin : PyTorch zip(내부 data.pkl) 또는 원시 pickle
- .npy / .npz : object dtype 배열 (allow_pickle 필요) 탐지
- .keras / .h5 : Lambda 레이어(직렬화된 파이썬 코드) 탐지
- .safetensors : 헤더 구조 검증 (코드 실행 불가 형식)
"""

from __future__ import annotations

import io
import json
import pickletools
import struct
import zipfile
import zlib
from dataclasses import dataclass, field
from pathlib import Path

from trustchain.core.files import iter_files, rel
from trustchain.core.findings import Finding, Severity

MODEL_SUFFIXES = (".pkl", ".pickle", ".joblib", ".dat", ".pt", ".pth", ".ckpt", ".bin", ".npy", ".npz",
                  ".keras", ".h5", ".hdf5", ".safetensors", ".onnx", ".gguf")
MAX_ENTRY_BYTES = 512 * 1024 * 1024
_STR_OPS = {"SHORT_BINUNICODE", "BINUNICODE", "BINUNICODE8", "UNICODE", "STRING", "BINSTRING", "SHORT_BINSTRING"}

DANGEROUS_MODULES = {
    "os", "posix", "nt", "subprocess", "sys", "socket", "shutil", "runpy", "pty", "commands", "webbrowser",
    "httplib", "http", "urllib", "urllib2", "requests", "ctypes", "importlib", "code", "codeop", "multiprocessing",
    "pickle", "_pickle", "cPickle", "dill", "marshal", "types", "platform", "tempfile", "asyncio", "signal",
    "pdb", "bdb", "timeit", "profile", "cProfile", "trace", "smtplib", "ftplib", "telnetlib", "paramiko",
}
DANGEROUS_GLOBALS = {
    "builtins.eval", "builtins.exec", "builtins.compile", "builtins.open", "builtins.__import__",
    "builtins.getattr", "builtins.setattr", "builtins.delattr", "builtins.globals", "builtins.locals",
    "builtins.breakpoint", "builtins.input", "__builtin__.eval", "__builtin__.exec", "__builtin__.execfile",
    "__builtin__.open", "__builtin__.__import__", "__builtin__.getattr", "__builtin__.apply",
    "operator.attrgetter", "operator.methodcaller", "numpy.testing._private.utils.runstring",
    "torch.hub.load", "torch.hub.download_url_to_file",
}
# 일반적인 ML 직렬화에 쓰이는 안전한 전역 (정확히 일치 또는 접두사)
SAFE_GLOBALS = {
    "collections.OrderedDict", "collections.defaultdict", "builtins.set", "builtins.frozenset", "builtins.slice",
    "builtins.bytearray", "builtins.complex", "builtins.dict", "builtins.list", "builtins.tuple", "builtins.object",
    "builtins.int", "builtins.float", "builtins.str", "builtins.bytes", "builtins.bool", "builtins.range",
    "_codecs.encode", "copy_reg._reconstructor", "copyreg._reconstructor", "__builtin__.set", "datetime.datetime",
    "datetime.date", "datetime.timedelta", "decimal.Decimal", "uuid.UUID", "pathlib.PosixPath", "pathlib.WindowsPath",
    "numpy.dtype", "numpy.ndarray", "numpy.core.multiarray._reconstruct", "numpy._core.multiarray._reconstruct",
    "numpy.core.multiarray.scalar", "numpy._core.multiarray.scalar", "numpy.random._pickle.__randomstate_ctor",
    "numpy.random._pickle.__bit_generator_ctor", "numpy.random._pickle.__generator_ctor",
}
SAFE_PREFIXES = ("torch._utils.", "torch.", "numpy.", "sklearn.", "scipy.sparse.", "pandas.core.", "pandas._libs.",
                 "xgboost.", "lightgbm.", "joblib.numpy_pickle.", "transformers.", "tokenizers.", "catboost.")
# 안전 접두사 안에서도 위험한 것
UNSAFE_UNDER_SAFE = ("torch.hub", "torch.load", "torch.jit", "torch.serialization", "torch.utils.cpp_extension",
                     "torch._dynamo", "torch.fx", "numpy.testing", "numpy.distutils", "numpy.f2py", "numpy.load")


@dataclass
class ModelScanResult:
    path: str
    format: str
    globals: list[str] = field(default_factory=list)
    dangerous: list[str] = field(default_factory=list)
    unknown: list[str] = field(default_factory=list)
    issues: list[str] = field(default_factory=list)

    @property
    def safe(self) -> bool:
        return not self.dangerous and not self.issues


def classify_global(g: str) -> str:
    """'dangerous' | 'safe' | 'unknown'."""
    g = g.replace(" ", ".").replace("\n", ".")
    mod = g.split(".")[0]
    if g in DANGEROUS_GLOBALS or mod in DANGEROUS_MODULES:
        return "dangerous"
    if g in SAFE_GLOBALS:
        return "safe"
    if any(g.startswith(p) for p in UNSAFE_UNDER_SAFE):
        return "dangerous"
    if any(g.startswith(p) for p in SAFE_PREFIXES):
        return "safe"
    return "unknown"


def pickle_globals(data: bytes | io.BufferedIOBase) -> tuple[list[str], list[str]]:
    """pickle 스트림의 전역 참조 목록과 파싱 이슈. 여러 pickle 이 이어져 있어도 끝까지 읽는다."""
    stream = io.BytesIO(data) if isinstance(data, (bytes, bytearray)) else data
    found: list[str] = []
    issues: list[str] = []
    strings: list[str] = []  # STACK_GLOBAL 용 최근 문자열 push
    memo: dict[int, str] = {}
    n_pickles = 0
    while True:
        start = stream.tell()
        head = stream.read(1)
        if not head:
            break
        stream.seek(start)
        try:
            memo_count = 0
            prev_str: str | None = None  # 직전 opcode 가 스택에 올린 문자열
            for op, arg, _pos in pickletools.genops(stream):
                name = op.name
                cur: str | None = None
                if name in _STR_OPS:
                    cur = str(arg)
                    strings.append(cur)
                elif name == "MEMOIZE":
                    if prev_str is not None:
                        memo[memo_count] = prev_str
                    memo_count += 1
                    cur = prev_str
                elif name in ("PUT", "BINPUT", "LONG_BINPUT"):
                    if prev_str is not None:
                        memo[int(arg)] = prev_str
                    cur = prev_str
                elif name in ("GET", "BINGET", "LONG_BINGET"):
                    cur = memo.get(int(arg))
                    if cur is not None:
                        strings.append(cur)
                elif name in ("GLOBAL", "INST"):
                    found.append(str(arg).replace(" ", "."))
                elif name == "STACK_GLOBAL":
                    if len(strings) >= 2:
                        found.append(f"{strings[-2]}.{strings[-1]}")
                    else:
                        found.append("<unresolved STACK_GLOBAL>")
                        issues.append("STACK_GLOBAL 의 대상을 정적으로 확인할 수 없습니다 (난독화 의심).")
                prev_str = cur
            n_pickles += 1
        except (ValueError, struct.error, EOFError, UnicodeDecodeError) as e:
            if n_pickles == 0:
                issues.append(f"pickle 파싱 실패: {e.__class__.__name__}")
            break
        # 다음 pickle 이 이어지는지 확인
        if stream.tell() == start:
            break
        nxt = stream.read(1)
        if not nxt or nxt not in (b"\x80", b"(", b"}", b"]", b"c"):
            break
        stream.seek(stream.tell() - 1)
    return list(dict.fromkeys(found)), issues


def _npy_uses_pickle(data: bytes) -> bool:
    if not data.startswith(b"\x93NUMPY"):
        return False
    major = data[6]
    if major == 1:
        hlen = struct.unpack("<H", data[8:10])[0]
        header = data[10 : 10 + hlen]
    else:
        hlen = struct.unpack("<I", data[8:12])[0]
        header = data[12 : 12 + hlen]
    return b"'descr': '|O'" in header or b"'descr': 'O'" in header or b"object" in header


def _keras_lambda(config_text: str) -> bool:
    return '"class_name": "Lambda"' in config_text or "'class_name': 'Lambda'" in config_text or \
        '"class_name":"Lambda"' in config_text


def _apply_globals(res: ModelScanResult, gl: list[str], issues: list[str]) -> None:
    res.globals.extend(gl)
    res.issues.extend(issues)
    for g in gl:
        c = classify_global(g) if not g.startswith("<") else "dangerous"
        if c == "dangerous":
            res.dangerous.append(g)
        elif c == "unknown":
            res.unknown.append(g)


def scan_model_file(path: Path, display: str | None = None) -> ModelScanResult:
    path = Path(path)
    suffix = path.suffix.lower()
    res = ModelScanResult(display or path.name, suffix.lstrip("."))
    with open(path, "rb") as fh:
        magic = fh.read(8)
    if suffix == ".safetensors":
        res.format = "safetensors"
        try:
            with open(path, "rb") as fh:
                n = struct.unpack("<Q", fh.read(8))[0]
                if n > 100 * 1024 * 1024:
                    raise ValueError("헤더 크기 이상")
                json.loads(fh.read(n))
        except (ValueError, struct.error):
            res.issues.append("safetensors 헤더가 손상되었거나 형식이 올바르지 않습니다.")
        return res
    if suffix in (".onnx", ".gguf"):
        res.format = suffix.lstrip(".")
        return res
    if magic.startswith(b"PK\x03\x04"):
        res.format = "zip:" + suffix.lstrip(".")
        try:
            with zipfile.ZipFile(path) as z:
                for info in z.infolist():
                    if info.file_size > MAX_ENTRY_BYTES:
                        res.issues.append(f"압축 내부 파일이 너무 큽니다: {info.filename}")
                        continue
                    lower = info.filename.lower()
                    if lower.endswith((".pkl", ".pickle")) or lower.endswith("data.pkl"):
                        _apply_globals(res, *pickle_globals(z.read(info)))
                    elif lower.endswith(".npy"):
                        if _npy_uses_pickle(z.read(info)[:4096]):
                            res.issues.append(f"{info.filename}: object 배열(pickle 역직렬화 필요)")
                    elif lower.endswith("config.json") and suffix == ".keras":
                        if _keras_lambda(z.read(info).decode("utf-8", "replace")):
                            res.dangerous.append("keras.layers.Lambda")
        except zipfile.BadZipFile:
            res.issues.append("zip 구조가 손상되었습니다.")
        return res
    if magic.startswith(b"\x89HDF"):
        res.format = "hdf5"
        with open(path, "rb") as fh:
            blob = fh.read(min(path.stat().st_size, 64 * 1024 * 1024))
        if _keras_lambda(blob.decode("latin-1")):
            res.dangerous.append("keras.layers.Lambda")
        return res
    if magic.startswith(b"\x93NUMPY"):
        res.format = "npy"
        with open(path, "rb") as fh:
            if _npy_uses_pickle(fh.read(4096)):
                res.issues.append("object dtype 배열: allow_pickle=True 로만 로드 가능 (pickle 실행)")
        return res
    # 원시 pickle (joblib zlib 압축 포함)
    data = path.read_bytes() if path.stat().st_size <= MAX_ENTRY_BYTES else b""
    if not data:
        res.issues.append("파일이 너무 커서 검사하지 못했습니다.")
        return res
    if data[:1] == b"\x78":  # zlib
        try:
            data = zlib.decompress(data)
            res.format = "joblib-zlib"
        except zlib.error:
            pass
    if data[:1] in (b"\x80", b"(", b"}", b"]", b"c") or suffix in (".pkl", ".pickle", ".joblib"):
        res.format = res.format if res.format.startswith("joblib") else "pickle"
        _apply_globals(res, *pickle_globals(data))
    return res


def scan_models(root: Path, exclude: list[str], project_root: Path | None = None) -> tuple[list[ModelScanResult], list[Finding]]:
    project_root = project_root or root
    results, findings = [], []
    for p in iter_files(root, MODEL_SUFFIXES, exclude):
        r = scan_model_file(p, rel(p, project_root))
        results.append(r)
        if r.dangerous:
            findings.append(Finding(
                rule_id="TC-MODEL-001", title="악성 코드가 포함된 모델 파일", severity=Severity.CRITICAL,
                category="model", file=r.path,
                message=f"모델 로드 시 실행될 위험 호출이 포함되어 있습니다: {', '.join(sorted(set(r.dangerous))[:5])}",
                fix="출처를 확인할 수 없는 모델은 사용하지 마세요. safetensors/.keras(safe_mode) 형식으로 교체하고 "
                    "AI-BOM 의 가중치 해시와 대조하세요.", cwe="CWE-502", tool="trustchain-modelscan",
                extra={"globals": r.globals[:50]},
            ))
        elif r.issues:
            findings.append(Finding(
                rule_id="TC-MODEL-002", title="검증이 필요한 모델 파일", severity=Severity.HIGH, category="model",
                file=r.path, message="; ".join(r.issues), cwe="CWE-502", tool="trustchain-modelscan",
                fix="코드 실행이 불가능한 형식(safetensors)으로 변환하거나, 격리 환경에서 검증하세요.",
            ))
        elif r.unknown:
            findings.append(Finding(
                rule_id="TC-MODEL-003", title="허용 목록에 없는 pickle 전역 참조", severity=Severity.MEDIUM,
                category="model", file=r.path,
                message=f"알 수 없는 전역 참조: {', '.join(sorted(set(r.unknown))[:5])}", cwe="CWE-502",
                tool="trustchain-modelscan", fix="참조 대상이 신뢰할 수 있는 라이브러리인지 확인하세요.",
            ))
        elif r.format in ("pickle", "joblib-zlib") or r.format.startswith("zip:p") or r.format == "zip:bin":
            findings.append(Finding(
                rule_id="TC-MODEL-004", title="pickle 기반 모델 형식", severity=Severity.LOW, category="model",
                file=r.path, message="위험 호출은 없지만 pickle 기반 형식입니다. 로드 시 코드 실행이 가능한 형식입니다.",
                fix="safetensors 또는 .keras 형식 사용을 권장합니다.", tool="trustchain-modelscan",
            ))
    return results, findings
