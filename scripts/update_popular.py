"""인기 PyPI 패키지 목록 갱신 (타이포스쿼팅 비교 기준).

hugovk/top-pypi-packages 의 최근 30일 다운로드 상위 목록에서 상위 N개를 가져와
src/trustchain/data/popular_packages.txt 를 다시 쓴다.

    python scripts/update_popular.py --top 1000
"""

from __future__ import annotations

import argparse
from pathlib import Path

import httpx

URL = "https://hugovk.github.io/top-pypi-packages/top-pypi-packages-30-days.min.json"
OUT = Path(__file__).resolve().parents[1] / "src" / "trustchain" / "data" / "popular_packages.txt"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--top", type=int, default=1000)
    args = ap.parse_args()
    r = httpx.get(URL, timeout=30, follow_redirects=True)
    r.raise_for_status()
    rows = r.json()["rows"][: args.top]
    header = ("# 인기 PyPI 패키지 목록 (타이포스쿼팅 비교 기준)\n"
              f"# 출처: {URL} (최근 30일 다운로드 상위 {args.top}개)\n")
    OUT.write_text(header + "\n".join(row["project"] for row in rows) + "\n", encoding="utf-8")
    print(f"{len(rows)}개 저장: {OUT}")


if __name__ == "__main__":
    main()
