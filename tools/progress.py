"""
課題の進み具合を表示する

    python tools/progress.py

EXERCISES.md の課題ごとに「必要な関数が実装されているか」を見て、
できているものに ✅、まだのものに ⬜ を付けるだけ。
テストを走らせずに現在地が分かるようにしてある。
"""

from __future__ import annotations

import importlib
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "chain"))

from util import enable_utf8_stdout                               # noqa: E402


# (課題名, モジュール名, 必要な属性...)
EXERCISES = [
    ("課題 1  RFC 6979（決定的 ECDSA）", "ecdsa", ["sign_rfc6979"]),
    ("課題 2  マークル木のドメイン分離", "merkle",
     ["safe_merkle_root", "safe_merkle_proof", "verify_safe_proof"]),
    ("課題 3  難易度の自動調整", "chain", ["retarget"]),
    ("課題 4  タイムスタンプ検証", "block", ["timestamp_ok"]),
    ("課題 5  SHA-256 を自作する", "hashing", ["sha256_from_scratch"]),
    ("課題 6  Schnorr 署名", "schnorr", ["sign", "verify", "challenge"]),
]

PHASES = [
    ("Phase 1  ハッシュ関数", "hashing"),
    ("Phase 2  楕円曲線 secp256k1", "curve"),
    ("Phase 3  ECDSA", "ecdsa"),
    ("Phase 4  マークル木", "merkle"),
    ("Phase 5  UTXO とトランザクション", "tx"),
    ("Phase 6  ブロックと PoW", "block"),
    ("Phase 7  最長鎖と合意", "chain"),
    ("Phase 8  P2P とノード間の伝播", "node"),
]


def status(module_name: str, needed: list[str]) -> tuple[bool, list[str]]:
    try:
        mod = importlib.import_module(module_name)
    except ImportError:
        return False, needed
    missing = [n for n in needed if not hasattr(mod, n)]
    return not missing, missing


def main() -> None:
    enable_utf8_stdout()

    print("\n  実装済みのフェーズ")
    print("  " + "-" * 56)
    for label, mod_name in PHASES:
        ok, _ = status(mod_name, [])
        print(f"  {'✅' if ok else '⬜'}  {label}")

    print("\n  課題（EXERCISES.md）")
    print("  " + "-" * 56)
    done = 0
    for label, mod_name, needed in EXERCISES:
        ok, missing = status(mod_name, needed)
        done += ok
        mark = "✅" if ok else "⬜"
        print(f"  {mark}  {label}")
        if not ok:
            where = f"chain/{mod_name}.py"
            print(f"        → {where} に {', '.join(missing)} を実装する")

    total = len(EXERCISES)
    bar_len = 28
    filled = round(bar_len * done / total)
    bar = "█" * filled + "░" * (bar_len - filled)
    print(f"\n  進捗  {bar}  {done}/{total}")

    if done == 0:
        print("\n  まずは EXERCISES.md の課題 1（RFC 6979）から。")
        print("  攻撃の再現を先に見ておくと動機が分かります:")
        print("      python chain/ecdsa.py")
    elif done < total:
        print("\n  次の課題は EXERCISES.md にシグネチャが書いてあります。")
        print("      python -m unittest tests.test_exercises -v")
    else:
        print("\n  全部塞ぎました。docs/roadmap.md の Phase 9 以降へ。")
    print()


if __name__ == "__main__":
    main()
