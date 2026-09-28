"""F3. 타이포스쿼팅 특징 추출.

인기 패키지 목록과 비교해 이름 기반 특징(편집거리, 키보드 인접 문자 치환,
문자 치환·접사 패턴, 문자 n-gram 임베딩 유사도)을 계산한다.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass
from functools import lru_cache
from importlib import resources

from packaging.utils import canonicalize_name

KEYBOARD_ROWS = ["1234567890-", "qwertyuiop", "asdfghjkl", "zxcvbnm"]
HOMOGLYPHS = [("0", "o"), ("1", "l"), ("l", "i"), ("1", "i"), ("5", "s"), ("rn", "m"), ("vv", "w"), ("cl", "d")]
AFFIXES = ["python-", "python3-", "py-", "py", "-python", "-py", "3", "2", "-dev", "-lib", "lib", "-sdk", "-api",
           "-client", "-utils", "-tools", "-core", "s"]


@lru_cache(maxsize=1)
def popular_packages() -> tuple[str, ...]:
    text = resources.files("trustchain.data").joinpath("popular_packages.txt").read_text(encoding="utf-8")
    names = [canonicalize_name(x.strip()) for x in text.splitlines() if x.strip() and not x.startswith("#")]
    return tuple(dict.fromkeys(names))


def _adjacent_map() -> dict[str, set[str]]:
    pos = {}
    for r, row in enumerate(KEYBOARD_ROWS):
        for c, ch in enumerate(row):
            pos[ch] = (r, c)
    adj: dict[str, set[str]] = {ch: set() for ch in pos}
    for a, (ra, ca) in pos.items():
        for b, (rb, cb) in pos.items():
            if a != b and abs(ra - rb) <= 1 and abs(ca - cb) <= 1:
                adj[a].add(b)
    return adj


ADJ = _adjacent_map()


def osa_distance(a: str, b: str, max_d: int | None = None) -> int:
    """Optimal String Alignment (Damerau-Levenshtein 제한형) 거리."""
    if a == b:
        return 0
    la, lb = len(a), len(b)
    if max_d is not None and abs(la - lb) > max_d:
        return max_d + 1
    prev2 = None
    prev = list(range(lb + 1))
    for i in range(1, la + 1):
        cur = [i] + [0] * lb
        row_min = cur[0]
        for j in range(1, lb + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            if prev2 is not None and i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                cur[j] = min(cur[j], prev2[j - 2] + 1)
            row_min = min(row_min, cur[j])
        if max_d is not None and row_min > max_d:
            return max_d + 1
        prev2, prev = prev, cur
    return prev[lb]


def _ngrams(s: str, ns=(2, 3)) -> Counter:
    s = f"^{s}$"
    c: Counter = Counter()
    for n in ns:
        for i in range(len(s) - n + 1):
            c[s[i : i + n]] += 1
    return c


def embed_similarity(a: str, b: str) -> float:
    """문자 n-gram 벡터 코사인 유사도 (이름 임베딩)."""
    va, vb = _ngrams(a), _ngrams(b)
    dot = sum(va[k] * vb[k] for k in va.keys() & vb.keys())
    na = math.sqrt(sum(v * v for v in va.values()))
    nb = math.sqrt(sum(v * v for v in vb.values()))
    return dot / (na * nb) if na and nb else 0.0


def _strip_sep(s: str) -> str:
    return re.sub(r"[-_.]", "", s)


def keyboard_substitution(a: str, b: str) -> bool:
    """한 글자만 다르고 그 글자가 키보드에서 인접한가."""
    if len(a) != len(b):
        return False
    diffs = [(x, y) for x, y in zip(a, b) if x != y]
    return len(diffs) == 1 and diffs[0][1] in ADJ.get(diffs[0][0], set())


def homoglyph_substitution(a: str, b: str) -> bool:
    for x, y in HOMOGLYPHS:
        for s, t in ((x, y), (y, x)):
            if s in a and a.replace(s, t) == b:
                return True
            # 한 곳만 치환
            idx = a.find(s)
            while idx != -1:
                if a[:idx] + t + a[idx + len(s) :] == b:
                    return True
                idx = a.find(s, idx + 1)
    return False


def affix_pattern(a: str, b: str) -> str | None:
    """구분자 변경, 접두/접미사 추가, 문자 중복·누락·자리바꿈 같은 전형적 위장 패턴."""
    if a != b and _strip_sep(a) == _strip_sep(b):
        return "구분자 변경"
    for af in AFFIXES:
        if a == b + af or a == af + b or a == b.replace("-", "") + af:
            return f"접사 '{af}' 추가"
    if len(a) == len(b) + 1:
        for i in range(len(a)):
            if a[:i] + a[i + 1 :] == b:
                dup = (i > 0 and a[i] == a[i - 1]) or (i + 1 < len(a) and a[i] == a[i + 1])
                return "문자 중복·삽입" if dup else "문자 삽입"
    if len(a) + 1 == len(b):
        for i in range(len(b)):
            if b[:i] + b[i + 1 :] == a:
                return "문자 누락"
    if len(a) == len(b):
        d = [i for i in range(len(a)) if a[i] != b[i]]
        if len(d) == 2 and d[1] == d[0] + 1 and a[d[0]] == b[d[1]] and a[d[1]] == b[d[0]]:
            return "문자 자리바꿈"
    return None


@dataclass
class NameFeatures:
    name: str
    is_popular: bool
    nearest: str | None
    distance: int
    similarity: float
    keyboard: bool
    homoglyph: bool
    pattern: str | None
    raw_mixed_case_confusable: bool  # 'jeIlyfish' 처럼 대문자 I 로 l 위장

    def vector(self) -> list[float]:
        return [
            self.similarity,
            1.0 / (1.0 + self.distance) if self.nearest else 0.0,
            float(self.keyboard),
            float(self.homoglyph or self.raw_mixed_case_confusable),
            float(self.pattern is not None),
            float(self.is_popular),
        ]


def name_features(name: str, raw_name: str | None = None, popular: tuple[str, ...] | None = None) -> NameFeatures:
    popular = popular or popular_packages()
    n = canonicalize_name(name)
    raw = raw_name or name
    is_pop = n in popular
    best, best_d, best_sim = None, 99, 0.0
    if not is_pop:
        for p in popular:
            if abs(len(p) - len(n)) > 3:
                continue
            d = osa_distance(n, p, max_d=3)
            if d > 3:
                if not (_strip_sep(n) == _strip_sep(p) or affix_pattern(n, p)):
                    continue
                d = 2
            sim = embed_similarity(n, p)
            if (d, -sim) < (best_d, -best_sim):
                best, best_d, best_sim = p, d, sim
        # 접사가 붙어 길이 차이가 큰 경우 (python-requests 등)
        if best is None:
            for p in popular:
                pat = affix_pattern(n, p)
                if pat:
                    best, best_d, best_sim = p, 2, embed_similarity(n, p)
                    break
    confusable = bool(re.search(r"I", raw)) and best is not None and canonicalize_name(raw.replace("I", "l")) == best
    return NameFeatures(
        name=n,
        is_popular=is_pop,
        nearest=best,
        distance=best_d if best else 99,
        similarity=best_sim,
        keyboard=bool(best and keyboard_substitution(n, best)),
        homoglyph=bool(best and homoglyph_substitution(n, best)),
        pattern=affix_pattern(n, best) if best else None,
        raw_mixed_case_confusable=confusable,
    )
