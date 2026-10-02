"""F11-2·3. 토크나이저(Kiwi 형태소 분석) · BM25 · 임베딩.

- Kiwi(kiwipiepy) 가 있으면 한국어 명사·동사 어간·외국어·숫자 형태소를 사용하고,
  없으면 정규식 토크나이저로 대체한다.
- CVE-2024-3094, GHSA-xxxx, 패키지명(python-dateutil), CWE-502 같은 식별자는
  형태소 분석 전에 통째로 보존한다 (정확한 용어 검색).
- 임베딩 : sentence-transformers 다국어 모델(기본 intfloat/multilingual-e5-small, 384차원).
  설치되지 않은 환경(테스트·오프라인)에서는 문자 n-gram 해싱 임베딩으로 대체한다.
"""

from __future__ import annotations

import hashlib
import logging
import math
import os
import re
from collections import Counter
from functools import lru_cache
from typing import Protocol, Sequence

ID_PATTERN = re.compile(
    r"(CVE-\d{4}-\d{4,7}|GHSA(?:-[23456789cfghjmpqrvwx]{4}){3}|PYSEC-\d{4}-\d+|CWE-\d+|[A-Za-z][A-Za-z0-9]*(?:[-_.][A-Za-z0-9]+)+)",
    re.I,
)
WORD = re.compile(r"[A-Za-z0-9]+|[가-힣]+")
KO_STOP = {"은", "는", "이", "가", "을", "를", "의", "에", "에서", "로", "으로", "와", "과", "도", "만", "하다", "있다", "되다",
           "수", "것", "등", "및", "어떻게", "무엇", "해야", "하나요", "인가요", "알려줘", "알려", "주세요"}
EN_STOP = {"the", "a", "an", "of", "to", "in", "and", "or", "is", "are", "for", "on", "with", "by", "be", "this",
           "that", "it", "as", "at", "from", "how", "what", "do", "i", "we"}


@lru_cache(maxsize=1)
def _kiwi():
    if os.environ.get("TRUSTCHAIN_NO_KIWI") == "1":
        return None
    try:
        from kiwipiepy import Kiwi

        return Kiwi()
    except Exception:  # 설치되지 않았거나 모델 로드 실패
        return None


def tokenize(text: str) -> list[str]:
    tokens: list[str] = []
    ids = [m.group(0).lower() for m in ID_PATTERN.finditer(text)]
    tokens.extend(ids)
    rest = ID_PATTERN.sub(" ", text)
    kiwi = _kiwi()
    if kiwi is not None:
        for t in kiwi.tokenize(rest):
            if t.tag.startswith(("NN", "SL", "SN", "VV", "VA", "XR", "SH")) and len(t.form) > 0:
                w = t.form.lower()
                if w not in KO_STOP and w not in EN_STOP:
                    tokens.append(w)
        return tokens
    for w in WORD.findall(rest):
        w = w.lower()
        if w in EN_STOP or w in KO_STOP:
            continue
        if re.match(r"[가-힣]", w):
            # 조사 제거 근사 : 흔한 조사 접미를 떼고, 2-gram 도 추가
            w2 = re.sub(r"(은|는|이|가|을|를|의|에서|에|으로|로|와|과|도|만|이란|란|하는|하면|해야|합니다|하나요)$", "", w)
            if w2:
                tokens.append(w2)
            if len(w2) >= 3:
                tokens.extend(w2[i : i + 2] for i in range(len(w2) - 1))
        else:
            tokens.append(w)
    return tokens


class BM25:
    """Okapi BM25 (k1=1.5, b=0.75). rank_bm25(BM25Okapi) 를 쓰고, 설치되지 않은 가벼운 환경에서만 자체 구현으로 대체한다.

    자체 구현은 idf = log(1 + (N-n+0.5)/(n+0.5)) 로 BM25Okapi(음수 idf 를 epsilon 하한으로 대체)와 점수가 조금 다르다.
    """

    def __init__(self, corpus_tokens: Sequence[Sequence[str]], k1: float = 1.5, b: float = 0.75):
        self.k1, self.b = k1, b
        self._lib = None
        self.backend = "builtin"
        if corpus_tokens:
            try:
                from rank_bm25 import BM25Okapi
            except ImportError:
                pass
            else:
                self._lib = BM25Okapi([list(t) for t in corpus_tokens], k1=k1, b=b)
                self.backend = "rank_bm25"
                return  # 라이브러리 색인만 사용 (운영 규모 지식베이스에서 같은 색인을 두 번 만들지 않음)
        self.docs = [Counter(t) for t in corpus_tokens]
        self.lens = [len(t) for t in corpus_tokens]
        self.avgdl = (sum(self.lens) / len(self.lens)) if self.lens else 0.0
        df: Counter = Counter()
        for d in self.docs:
            df.update(d.keys())
        n = len(self.docs)
        self.idf = {t: math.log(1 + (n - f + 0.5) / (f + 0.5)) for t, f in df.items()}

    def scores(self, query: Sequence[str]) -> list[float]:
        if self._lib is not None:
            return [float(x) for x in self._lib.get_scores(list(query))]
        out = []
        for d, dl in zip(self.docs, self.lens):
            s = 0.0
            for q in query:
                f = d.get(q)
                if not f:
                    continue
                s += self.idf.get(q, 0.0) * f * (self.k1 + 1) / (f + self.k1 * (1 - self.b + self.b * dl / (self.avgdl or 1)))
            out.append(s)
        return out


class Embedder(Protocol):
    dim: int

    def embed(self, texts: Sequence[str], is_query: bool = False) -> list[list[float]]: ...


class HashingEmbedder:
    """문자 n-gram(2~4) + 단어 해싱 임베딩 (외부 모델 없는 환경의 대체 구현)."""

    def __init__(self, dim: int = 384):
        self.dim = dim

    def _vec(self, text: str) -> list[float]:
        v = [0.0] * self.dim
        t = text.lower()
        feats = tokenize(text)
        s = re.sub(r"\s+", " ", t)
        feats += [s[i : i + n] for n in (3, 4) for i in range(max(0, len(s) - n + 1))]
        for f in feats:
            h = int.from_bytes(hashlib.blake2b(f.encode(), digest_size=8).digest(), "little")
            v[h % self.dim] += 1.0 if (h >> 63) & 1 else -1.0
        n = math.sqrt(sum(x * x for x in v)) or 1.0
        return [x / n for x in v]

    def embed(self, texts: Sequence[str], is_query: bool = False) -> list[list[float]]:
        return [self._vec(t) for t in texts]


# 기본 임베딩 모델과 리비전(HuggingFace 커밋) 고정 : 저장소가 바뀌어도 다른 가중치가 들어오지 않고 측정이 재현된다
EMBED_MODEL = "intfloat/multilingual-e5-small"
EMBED_REVISION = "614241f622f53c4eeff9890bdc4f31cfecc418b3"
# 그 리비전의 가중치 파일(model.safetensors) SHA-256 : 로드 전에 대조 (models.toml AI-BOM 선언과 같은 값)
EMBED_SHA256 = "1a55775f53449dac10a2bcbc312469fac40b96d53198c407081a831f81c98477"
WEIGHTS_FILE = "model.safetensors"


class ModelIntegrityError(RuntimeError):
    """고정한 가중치 해시와 실제 파일이 다름. 대체 구현으로 넘어가지 않고 로드를 거부한다 (fail-closed)."""


def verify_hf_weights(repo_id: str, revision: str, expected_sha256: str, filename: str = WEIGHTS_FILE) -> None:
    """HuggingFace 에서 고정 리비전의 가중치 파일을 받아(캐시 재사용) SHA-256 을 대조한다."""
    import hashlib

    from huggingface_hub import hf_hub_download

    path = hf_hub_download(repo_id, filename, revision=revision)
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    if h.hexdigest() != expected_sha256:
        raise ModelIntegrityError(f"{repo_id}@{revision[:12]} 가중치 해시가 고정값과 다릅니다 - 로드를 거부합니다")


def _revision(model_name: str, default_model: str, default_revision: str, env: str) -> str | None:
    """환경변수로 지정한 리비전 → 기본 모델이면 고정 리비전 → 그 밖의 모델은 None(사용자가 고정해야 함)."""
    return os.environ.get(env) or (default_revision if model_name == default_model else None)


class SentenceTransformerEmbedder:
    def __init__(self, model_name: str | None = None):
        from sentence_transformers import SentenceTransformer

        self.model_name = model_name or os.environ.get("TRUSTCHAIN_EMBED_MODEL", EMBED_MODEL)
        rev = _revision(self.model_name, EMBED_MODEL, EMBED_REVISION, "TRUSTCHAIN_EMBED_REVISION")
        if self.model_name == EMBED_MODEL and rev == EMBED_REVISION:
            verify_hf_weights(EMBED_MODEL, EMBED_REVISION, EMBED_SHA256)  # 해시 검증 후 로드
        self.model = SentenceTransformer(self.model_name, revision=rev)
        get_dim = getattr(self.model, "get_embedding_dimension", None) or self.model.get_sentence_embedding_dimension
        self.dim = int(get_dim())
        self.e5 = "e5" in self.model_name.lower()

    def embed(self, texts: Sequence[str], is_query: bool = False) -> list[list[float]]:
        if self.e5:
            texts = [("query: " if is_query else "passage: ") + t for t in texts]
        arr = self.model.encode(list(texts), normalize_embeddings=True, batch_size=32, show_progress_bar=False)
        return [list(map(float, row)) for row in arr]


def default_embedder() -> Embedder:
    if os.environ.get("TRUSTCHAIN_EMBEDDER", "auto") != "hashing":
        try:
            return SentenceTransformerEmbedder()
        except ModelIntegrityError:
            raise  # 변조 가능성 : 대체 구현으로 조용히 넘어가지 않는다
        except Exception as e:  # 모델 미설치/다운로드 불가 → 대체 구현
            logging.getLogger("trustchain.assistant").warning("모델을 불러오지 못해 대체 구현 사용 (검색 품질 저하): %s", e.__class__.__name__)
    return HashingEmbedder(int(os.environ.get("TRUSTCHAIN_EMBED_DIM", "384")))


def cosine(a: Sequence[float], b: Sequence[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    return dot / (na * nb) if na and nb else 0.0
