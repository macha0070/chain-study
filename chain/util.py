"""
共通の小道具。暗号的な中身はここには置かない。
"""

from __future__ import annotations

import sys


def enable_utf8_stdout() -> None:
    """Windows で出力をパイプ/リダイレクトしたときの文字化けを防ぐ。

    コンソールに直接出す分には問題ないが、`python demo.py > out.txt` や
    シェル経由でパイプすると locale (cp932) が使われて日本語が壊れる。
    """
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")


def section(title: str) -> None:
    print("\n" + "=" * 74)
    print(f"  {title}")
    print("=" * 74)
