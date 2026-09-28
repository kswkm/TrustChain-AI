"""F11-1. 지식베이스 수집·청킹.

문서 구조 단위로 분할한다.
- OSV/NVD 권고문 : 요약·상세(취약점 설명) / 영향 버전 / 조치 방법 / 참고
- CWE : 설명 / 확장 설명 / 완화 방법
- KISA 시큐어코딩 가이드 요약(knowledge/kisa/*.md) : '## ' 제목 단위, 긴 절은 문단 단위로 분할
"""

from __future__ import annotations

import csv
import io
import json
import re
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any, Iterable

MAX_CHARS = 1200


@dataclass
class Chunk:
    chunk_id: str
    doc_id: str
    source: str  # osv | nvd | cwe | kisa | local
    title: str
    section: str
    text: str
    meta: dict[str, Any] = field(default_factory=dict)


def _split_long(text: str, limit: int = MAX_CHARS) -> list[str]:
    if len(text) <= limit:
        return [text]
    parts, buf = [], ""
    for para in re.split(r"\n\s*\n", text):
        if len(buf) + len(para) + 2 > limit and buf:
            parts.append(buf.strip())
            buf = ""
        while len(para) > limit:
            cut = para.rfind(". ", 0, limit)
            cut = cut + 1 if cut > limit // 2 else limit
            parts.append(para[:cut].strip())
            para = para[cut:]
        buf += para + "\n\n"
    if buf.strip():
        parts.append(buf.strip())
    return parts


def chunk_osv(v: dict[str, Any]) -> list[Chunk]:
    vid = v.get("id", "")
    aliases = v.get("aliases", []) or []
    title = f"{vid} {('(' + ', '.join(aliases) + ')') if aliases else ''} {v.get('summary', '')}".strip()
    pkgs = sorted({(a.get("package") or {}).get("name", "") for a in v.get("affected", []) or []} - {""})
    meta = {"id": vid, "aliases": aliases, "packages": pkgs,
            "url": f"https://osv.dev/vulnerability/{vid}", "published": v.get("published")}
    out: list[Chunk] = []
    desc = "\n\n".join(x for x in (v.get("summary"), v.get("details")) if x)
    for i, part in enumerate(_split_long(desc) if desc else []):
        out.append(Chunk(f"osv:{vid}:desc:{i}", f"osv:{vid}", "osv", title, "취약점 설명",
                         f"{title}\n{part}", meta))
    ranges = []
    fixed = []
    for a in v.get("affected", []) or []:
        pkg = (a.get("package") or {})
        for r in a.get("ranges", []) or []:
            evs = ", ".join(f"{k} {val}" for e in r.get("events", []) for k, val in e.items())
            ranges.append(f"{pkg.get('ecosystem')}/{pkg.get('name')}: {evs}")
            fixed += [e["fixed"] for e in r.get("events", []) if "fixed" in e]
        if a.get("versions"):
            ranges.append(f"{pkg.get('name')} 영향 버전 목록: {', '.join(a['versions'][:30])}")
    if ranges:
        out.append(Chunk(f"osv:{vid}:affected", f"osv:{vid}", "osv", title, "영향 버전",
                         f"{title}\n영향 범위\n" + "\n".join(ranges), meta))
    if fixed or pkgs:
        fix_text = (f"{', '.join(pkgs)} 를 {', '.join(sorted(set(fixed)))} 이상으로 업그레이드하면 해결됩니다."
                    if fixed else "공식 패치 버전 정보가 없습니다. 권고문의 완화 방법을 확인하세요.")
        out.append(Chunk(f"osv:{vid}:fix", f"osv:{vid}", "osv", title, "조치 방법", f"{title}\n조치 방법: {fix_text}",
                         {**meta, "fixed": sorted(set(fixed))}))
    return out


def chunk_cwe_csv(text: str) -> list[Chunk]:
    """MITRE CWE CSV (cwe.mitre.org/data/csv/1000.csv.zip 압축 해제본)."""
    out: list[Chunk] = []
    reader = csv.DictReader(io.StringIO(text))
    for row in reader:
        cid = (row.get("CWE-ID") or "").strip()
        if not cid:
            continue
        cwe = f"CWE-{cid}"
        name = row.get("Name", "")
        meta = {"id": cwe, "url": f"https://cwe.mitre.org/data/definitions/{cid}.html"}
        title = f"{cwe}: {name}"
        for sec, key in (("설명", "Description"), ("확장 설명", "Extended Description"),
                         ("완화 방법", "Potential Mitigations")):
            val = (row.get(key) or "").strip()
            if not val:
                continue
            val = re.sub(r"::|:(PHASE|STRATEGY|DESCRIPTION|EFFECTIVENESS):", "\n", val)
            for i, part in enumerate(_split_long(val)):
                out.append(Chunk(f"cwe:{cid}:{key}:{i}", f"cwe:{cid}", "cwe", title, sec, f"{title}\n{sec}: {part}",
                                 meta))
    return out


def chunk_markdown(text: str, doc_id: str, source: str, meta: dict[str, Any] | None = None) -> list[Chunk]:
    meta = meta or {}
    title_m = re.search(r"^#\s+(.+)$", text, re.M)
    doc_title = title_m.group(1).strip() if title_m else doc_id
    out: list[Chunk] = []
    sections = re.split(r"(?m)^##\s+", text)
    for si, sec in enumerate(sections[1:] if len(sections) > 1 else sections):
        head, _, body = sec.partition("\n")
        head = head.strip() if len(sections) > 1 else doc_title
        body = re.sub(r"^#\s+.+$", "", body, flags=re.M).strip()
        # 절 제목에 CWE 번호가 있으면 메타데이터에 기록
        cwes = re.findall(r"CWE-\d+", head + " " + body[:200])
        for i, part in enumerate(_split_long(body)):
            out.append(Chunk(f"{doc_id}:{si}:{i}", doc_id, source, f"{doc_title} - {head}", head,
                             f"[{doc_title}] {head}\n{part}", {**meta, "cwe": sorted(set(cwes))}))
    return out


def builtin_knowledge() -> list[Chunk]:
    """패키지에 포함된 KISA 시큐어코딩 가이드 요약·공급망 보안 지식 문서."""
    out: list[Chunk] = []
    base = resources.files("trustchain.knowledge")
    for sub in ("kisa", "cwe", "supply"):
        d = base.joinpath(sub)
        if not d.is_dir():
            continue
        for f in sorted(d.iterdir(), key=lambda x: x.name):
            if f.name.endswith(".md"):
                doc_id = f"{sub}:{f.name[:-3]}"
                out.extend(chunk_markdown(f.read_text(encoding="utf-8"), doc_id, sub,
                                          {"file": f"knowledge/{sub}/{f.name}"}))
    # 시연·평가용 OSV 권고문 샘플 (osv.dev API 원본, CC-BY 4.0 등 각 데이터베이스 라이선스)
    osv_dir = base.joinpath("osv")
    if osv_dir.is_dir():
        for f in sorted(osv_dir.iterdir(), key=lambda x: x.name):
            if f.name.endswith(".json"):
                try:
                    out.extend(chunk_osv(json.loads(f.read_text(encoding="utf-8"))))
                except ValueError:
                    continue
    return out


def load_osv_dir(path: Path) -> Iterable[Chunk]:
    """OSV 덤프 디렉터리(예: PyPI all.zip 압축 해제) 의 *.json."""
    for p in sorted(Path(path).glob("*.json")):
        try:
            yield from chunk_osv(json.loads(p.read_text(encoding="utf-8")))
        except (ValueError, OSError):
            continue
