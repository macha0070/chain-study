"""
通し実行

    python chain/demo.py            全フェーズを順に走らせる
    python chain/demo.py --check    自己確認だけ（数秒で終わる）

ハッシュ → 楕円曲線 → 署名 → マークル木 → UTXO → ブロック → 合意 の順で、
下の層が上の層に効いてくる様子を出力で追えるようにしてある。

出力を眺めるだけでは身につかない。docs/roadmap.md の「手を動かす課題」を必ずやること。
"""

from __future__ import annotations

import sys

from util import enable_utf8_stdout, section

import hashing
import curve
import ecdsa
import merkle
import tx
import block
import chain
import node
import scenario


PHASES = [
    ("Phase 1  ハッシュ関数 — 改ざん検出と PoW はここから出てくる", hashing),
    ("Phase 2  楕円曲線 secp256k1 — 鍵ペアの正体は掛け算 1 回", curve),
    ("Phase 3  ECDSA — 署名と、nonce を外した瞬間の破滅", ecdsa),
    ("Phase 4  マークル木 — 全部持たずに確かめる", merkle),
    ("Phase 5  UTXO — 残高という概念を持たない台帳", tx),
    ("Phase 6  ブロック — 順序を固定する箱", block),
    ("Phase 7  合意 — 最長鎖と、確定が確率でしかないこと", chain),
    ("Phase 8  P2P — 遅延がある限り、分岐は通常運転", node),
    ("シナリオ  51% 攻撃を頭から流す", scenario),
]


def run_checks() -> None:
    section("自己確認")
    for _, mod in PHASES:
        mod.self_check()
    print("\n  すべて通過。")


def main() -> None:
    enable_utf8_stdout()

    if "--check" in sys.argv:
        run_checks()
        return

    run_checks()
    for title, mod in PHASES:
        section(title)
        mod.demo()

    section("まとめ — 7 つの部品で何ができたか")
    print("""
  組み上がったもの:

    ハッシュ        1 ビットの改ざんが全体に伝播する。PoW の難易度は 2^d そのもの。
    楕円曲線        公開鍵 = d*G。逆を解く壁が 2^128。
    ECDSA           「本人が承認した」を秘密鍵を見せずに示す。
    マークル木      N 件の tx を 32 バイトに要約し、包含証明は log2(N) 個。
    UTXO            残高を持たない台帳。検証ルールはたった 5 本。
    ブロック        prev_hash + PoW で順序を固定する。
    最長鎖          最大仕事量の枝を正とする。投票ではない。
    P2P             分岐は攻撃ではなく伝播遅延の帰結。孤児率 ≈ 遅延 / ブロック間隔。

  そして壊れたもの（このリポジトリで実際に再現した 4 つ）:

    1. nonce 使い回し        署名 2 本から秘密鍵が復元できた。曲線は無傷のまま。
                             → 対策は RFC 6979（決定的 ECDSA）
    2. CVE-2012-2459         中身の違う tx リストが同じマークル根を持った。
                             → 対策は重複段の拒否 / ドメイン分離ハッシュ
    3. リオーグによる二重支払い  3 確認済みの支払いが、後から現れた長い枝で消えた。
                             → 対策は「深く待つ」だけ。確定は最後まで確率的
    4. 敵対的入力での DoS    負の額を持つ tx が、検証で弾かれる前に直列化で例外を投げた。
                             → テストが見つけた。修正済み (tx.core_bytes の signed=True)

  ここから見えること:

    暗号は 1 つも破られていない。破れたのは全部、実装の選択と経済的な前提のほう。
    「安全」とは数学的な不可能性ではなく、攻撃費用が引き合わないという状態を指す。

  次に読むもの:

    - 中本論文 "Bitcoin: A Peer-to-Peer Electronic Cash System" (2008) 第 11 節
      → chain.attacker_success_probability() が、その式そのもの
    - docs/roadmap.md の発展課題（RFC 6979、ドメイン分離、難易度調整、eclipse、PoS）

  手を動かすなら:

    docker compose up   →  http://localhost:8000
    ブラウザから同じ攻撃を実行して、チェーンの枝が載せ替わる様子を見る。
""")


if __name__ == "__main__":
    main()
