"""
Phase 4: マークル木 — 「全部持たなくても確かめられる」を作る

なぜ必要か
----------
ブロックには何千もの tx が入る。ブロックヘッダは 80 バイトしかない。
この矛盾を埋めるのがマークル木で、木の根 32 バイトだけをヘッダに書く。

そうすると 2 つの効果が同時に出る。

    1. 改ざん検出   tx を 1 つでも書き換えると根が変わる（ハッシュの雪崩効果）
    2. 包含証明     「この tx はこのブロックに入っている」を
                    log2(N) 個のハッシュだけで証明できる（SPV / 軽量ノード）

スマホのウォレットが数百 GB のチェーンを持たずに動けるのは 2 のおかげ。

到達点
------
- tx を 1 つ書き換えると根が変わることを確認する
- N = 1024 の証明が 10 個のハッシュで済むことを数える
- 【本題】Bitcoin の「奇数なら最後を複製」ルールが、
  中身の違う 2 つのブロックに同じ根を与えてしまうことを再現する (CVE-2012-2459)
"""

from __future__ import annotations

from dataclasses import dataclass

from hashing import dH


# ---------------------------------------------------------------- 木を作る

def merkle_root(leaves: list[bytes]) -> bytes:
    """葉のリストから根を計算する（Bitcoin 方式）。

    ペアにして繋げてハッシュ、を段が 1 つになるまで繰り返す。
    段の要素数が奇数のときは最後の 1 つを自分自身と組ませる。
    このルールがあとで問題を起こす（demo の観察 3）。
    """
    if not leaves:
        return bytes(32)                       # 空ブロックの根はゼロとする
    level = list(leaves)
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])            # 最後を複製
        level = [dH(level[i] + level[i + 1]) for i in range(0, len(level), 2)]
    return level[0]


@dataclass(frozen=True)
class ProofStep:
    """証明の 1 段ぶん。sibling とその左右。"""
    sibling: bytes
    is_left: bool                              # sibling が左側なら True

    def __repr__(self) -> str:
        side = "L" if self.is_left else "R"
        return f"{side}:{self.sibling[:4].hex()}"


def merkle_proof(leaves: list[bytes], index: int) -> list[ProofStep]:
    """index 番目の葉に対する包含証明（= 各段の兄弟ハッシュ）を作る。

    根まで登る途中で「相方だったハッシュ」を集めるだけ。
    木の高さぶん、つまり log2(N) 個で終わる。
    """
    assert 0 <= index < len(leaves)
    proof: list[ProofStep] = []
    level = list(leaves)
    idx = index
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        sibling_idx = idx ^ 1                  # 偶数なら右隣、奇数なら左隣
        proof.append(ProofStep(level[sibling_idx], is_left=(sibling_idx < idx)))
        level = [dH(level[i] + level[i + 1]) for i in range(0, len(level), 2)]
        idx //= 2
    return proof


def verify_proof(leaf: bytes, proof: list[ProofStep], root: bytes) -> bool:
    """葉と証明から根を組み立て直して照合する。

    検証側が持っているのは「葉 1 つ + 証明 + 根」だけ。
    ブロックの中身は 1 バイトも要らない。これが SPV。
    """
    cur = leaf
    for step in proof:
        cur = dH(step.sibling + cur) if step.is_left else dH(cur + step.sibling)
    return cur == root


# ---------------------------------------------------------------- 自己確認

def _leaves(n: int, tag: bytes = b"tx") -> list[bytes]:
    return [dH(tag + str(i).encode()) for i in range(n)]


def self_check() -> None:
    # 葉が 1 枚なら根は葉そのもの
    one = _leaves(1)
    assert merkle_root(one) == one[0]

    # 全インデックスで証明が通る（2 の冪でも半端な数でも）
    for n in (1, 2, 3, 4, 5, 7, 8, 16, 33):
        leaves = _leaves(n)
        root = merkle_root(leaves)
        for i in range(n):
            proof = merkle_proof(leaves, i)
            assert verify_proof(leaves[i], proof, root), f"n={n} i={i} で証明が通らない"
        # 偽の葉では通らない
        assert not verify_proof(dH(b"fake"), merkle_proof(leaves, 0), root)

    # 1 枚差し替えると根が変わる
    leaves = _leaves(8)
    root = merkle_root(leaves)
    tampered = list(leaves)
    tampered[3] = dH(b"tampered")
    assert merkle_root(tampered) != root

    # 証明の長さは天井 log2(N)
    assert len(merkle_proof(_leaves(1024), 0)) == 10

    print("  [ok] merkle.py 自己確認 通過")


def demo() -> None:
    print("\n-- 観察 1: 根は全 tx を要約している ----------------------------")
    leaves = _leaves(8)
    root = merkle_root(leaves)
    print(f"    tx 8 件の根 = {root.hex()}")
    tampered = list(leaves)
    tampered[3] = dH(b"tx3-tampered")
    print(f"    tx[3] だけ差し替えた根 = {merkle_root(tampered).hex()}")
    print("    → ヘッダの 32 バイトを守るだけで、中の全 tx が守られる。")

    print("\n-- 観察 2: 証明サイズは log2(N) --------------------------------")
    print(f"    {'tx 件数 N':>10} {'証明のハッシュ数':>18} {'証明サイズ':>12} {'全部持つ場合':>14}")
    print("    " + "-" * 58)
    for n in (4, 16, 256, 1024, 4096, 1_000_000):
        proof = merkle_proof(_leaves(n), 0)
        print(f"    {n:>10,} {len(proof):>18} {len(proof) * 32:>10,} B "
              f"{n * 32:>12,} B")
    print("""
    → 100 万件の tx を含むブロックでも、証明は 20 個 = 640 バイト。
      スマホのウォレットがフルノードを持たずに入金を確認できる理由がこれ。
      ただし「根が正しい」ことは別途、PoW の積み上がりを見て信じている。
""")

    print("-- 観察 3【本題】奇数複製ルールの穴 (CVE-2012-2459) ------------")
    print("  段の要素数が奇数なら最後を複製する、というルールを思い出す。")
    print("  では [a, b, c] と [a, b, c, c] の根はどうなるか？")
    a, b, c = _leaves(3, tag=b"real-tx")
    r3 = merkle_root([a, b, c])
    r4 = merkle_root([a, b, c, c])
    print(f"\n    root([a,b,c])    = {r3.hex()}")
    print(f"    root([a,b,c,c])  = {r4.hex()}")
    print(f"    一致 = {r3 == r4}")
    print("""
    → 中身の違う 2 つの tx リストが、同じ根を持ってしまった。
      根が同じならブロックヘッダも同じ、ハッシュも同じ、PoW もそのまま流用できる。

    → 実害: 攻撃者は正当なブロックの tx リストを [a,b,c,c] に膨らませて配る。
      受け取ったノードは「c が二重支払いだ」と判断してこのブロックを invalid と
      記録する。ところがブロックハッシュは正規版と同一なので、正規のブロックまで
      永久に invalid 扱いされ、ノードがチェーンから切り離される。
      2012 年に Bitcoin Core が緊急パッチを出した実在の脆弱性。

    → 教訓: マークル木は「木の形」を根に含めていない。
      対策は (a) 重複した段を拒否する、(b) 葉と内部ノードでハッシュの
      ドメインを分ける（RFC 6962 / Certificate Transparency はこちら）。
      → docs/roadmap.md の発展課題 2 で塞ぐ。
""")


if __name__ == "__main__":
    from util import enable_utf8_stdout

    enable_utf8_stdout()
    self_check()
    demo()
