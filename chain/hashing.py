"""
Phase 1: ハッシュ関数 — ブロックチェーンの「接着剤」

なぜ必要か
----------
ブロックチェーンの性質はほぼ全部、暗号学的ハッシュ関数 H の 3 つの性質から出てくる。

    1. 原像困難    H(x) から x を求めるのが困難
    2. 衝突困難    H(x) = H(y) となる x != y を見つけるのが困難
    3. 雪崩効果    x を 1 ビット変えると H(x) が「別物」になる

「前のブロックのハッシュを次のブロックに書く」だけで改ざんが検出できるのは 3 のおかげ。
Proof of Work が「計算量を燃やした証明」になるのは 1 のおかげ。
つまり H を理解しないと、後のすべてが手品に見える。

方針メモ
--------
SHA-256 そのものは自作しない（hashlib を使う）。ここでの目的は
「H はランダムオラクルのように振る舞う」を数字で確認することであって、
圧縮関数の中身ではないため。SHA-256 の自作は docs/roadmap.md の発展課題に置いた。

到達点
------
- 1 ビット変えたときに変化する出力ビット数の平均が 128 (= 256 / 2) に張り付く
- 先頭 d ビットを 0 にする nonce 探しの平均試行回数が 2^d に一致する
  → この 1 本の式が、そのまま「難易度」と「電気代」の正体
"""

from __future__ import annotations

import hashlib
import os
import time


# ---------------------------------------------------------------- 基本

def H(data: bytes) -> bytes:
    """SHA-256。"""
    return hashlib.sha256(data).digest()


def dH(data: bytes) -> bytes:
    """SHA-256 の 2 段掛け。

    Bitcoin がブロックヘッダと tx に使っているのはこちら。
    長さ拡張攻撃 (length extension) を潰すための保険であって、
    ここでの観察結果は 1 段でも 2 段でも変わらない。
    """
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def hexd(data: bytes) -> str:
    return data.hex()


# ---------------------------------------------------------------- 観察 1: 雪崩効果

def flip_bit(data: bytes, i: int) -> bytes:
    """data の i ビット目を反転する。"""
    b = bytearray(data)
    b[i // 8] ^= 1 << (i % 8)
    return bytes(b)


def hamming(a: bytes, b: bytes) -> int:
    """2 つのバイト列で異なるビットの個数。"""
    return sum(bin(x ^ y).count("1") for x, y in zip(a, b))


def avalanche(trials: int = 2000, msg_len: int = 32) -> float:
    """入力 1 ビット反転に対して、出力が平均何ビット変わるかを測る。

    理想的なハッシュ（= 出力が入力と無関係な一様乱数）なら、
    256 ビットそれぞれが確率 1/2 で反転するので期待値はちょうど 128。
    """
    total = 0
    for _ in range(trials):
        msg = os.urandom(msg_len)
        i = int.from_bytes(os.urandom(2), "big") % (msg_len * 8)
        total += hamming(H(msg), H(flip_bit(msg, i)))
    return total / trials


# ---------------------------------------------------------------- 観察 2: PoW

def leading_zero_bits(digest: bytes) -> int:
    """ダイジェスト先頭に 0 ビットが何個並んでいるか。"""
    n = 0
    for byte in digest:
        if byte == 0:
            n += 8
            continue
        n += 8 - byte.bit_length()   # 上位側の 0 を数える
        break
    return n


def meets_difficulty(digest: bytes, difficulty: int) -> bool:
    """先頭 difficulty ビットが 0 か。これが PoW の合否判定そのもの。"""
    return leading_zero_bits(digest) >= difficulty


def mine(prefix: bytes, difficulty: int, start: int = 0) -> tuple[int, bytes, int]:
    """H(prefix || nonce) の先頭が 0 で difficulty ビット埋まる nonce を探す。

    やっていることは「当たりが出るまでサイコロを振る」だけ。
    ハッシュの原像困難性から、これ以上に賢い方法が存在しない。
    そこが重要で、だから「探索の成功 = 計算量を消費した証拠」になる。

    Returns: (nonce, digest, 試行回数)
    """
    nonce = start
    while True:
        digest = H(prefix + nonce.to_bytes(8, "big"))
        if meets_difficulty(digest, difficulty):
            return nonce, digest, nonce - start + 1
        nonce += 1


# ---------------------------------------------------------------- 自己確認

def self_check() -> None:
    assert H(b"abc") == H(b"abc")                                  # 決定性
    assert hexd(H(b"abc")).startswith("ba7816bf8f01cfea")          # 既知の値
    assert H(b"abc") != H(b"abd")                                  # 1 バイト違えば別物
    assert leading_zero_bits(bytes([0x00, 0x0F])) == 12
    assert leading_zero_bits(bytes([0x80])) == 0
    assert leading_zero_bits(bytes([0x01])) == 7
    assert meets_difficulty(bytes([0x00, 0xFF]), 8)
    assert not meets_difficulty(bytes([0x00, 0xFF]), 9)
    print("  [ok] hashing.py 自己確認 通過")


def demo() -> None:
    print("\n-- 観察 1: 雪崩効果 --------------------------------------------")
    print("  入力を 1 ビットだけ変えると、256 ビットの出力は何ビット変わるか？")
    msg = b"blockchain from scratch"
    a, b = H(msg), H(flip_bit(msg, 0))
    print(f"    H(msg)       = {hexd(a)}")
    print(f"    H(msg^1bit)  = {hexd(b)}")
    print(f"    異なるビット数 = {hamming(a, b)} / 256")
    avg = avalanche(trials=2000)
    print(f"\n    2000 回試行の平均 = {avg:.2f} ビット   (理想値 128.00)")
    print("    → 出力は入力の『似ている度合い』を一切引き継がない。")
    print("      これが『1 文字直したらチェーン全体が壊れる』の正体。")

    print("\n-- 観察 2: 難易度と仕事量 --------------------------------------")
    print("  先頭 d ビットが 0 になる nonce を探す。理論上の平均試行回数は 2^d。")
    print("  d ごとに prefix を変えて複数回まわし平均を取る（1 回だと運が乗る）。")
    head = f"    {'d':>3} {'回数':>4} {'平均試行回数':>14} {'2^d':>12} {'実測/2^d':>9} {'合計秒':>7}"
    print("\n" + head)
    print("    " + "-" * 56)
    for d in range(4, 23, 3):
        trials = 40 if d <= 12 else (8 if d <= 17 else 2)
        t0 = time.perf_counter()
        total = 0
        for k in range(trials):
            _, _, tries = mine(b"header|%d|%d|" % (d, k), d)
            total += tries
        dt = time.perf_counter() - t0
        avg_tries = total / trials
        print(f"    {d:>3} {trials:>4} {avg_tries:>14,.0f} {2**d:>12,} "
              f"{avg_tries / 2**d:>9.2f} {dt:>7.2f}")
    print("""
    → 実測/2^d が 1 の周りに散る。試行回数は幾何分布なのでばらつきは大きいが、
      中心は必ず 2^d。d を 1 増やすたびに仕事量が 2 倍、線形ではなく指数。

    → Bitcoin は「10 分に 1 ブロック」を保つためこの d を自動調整している。
      ネットワーク全体の計算力が 2 倍になったら d を 1 上げればつり合う。

    → 逆に検証はハッシュ 1 回で済む。作るのは高価、確かめるのは安い。
      この非対称性は Phase 0（離散対数）で見たものとまったく同じ形をしている。
""")


if __name__ == "__main__":
    from util import enable_utf8_stdout

    enable_utf8_stdout()
    self_check()
    demo()
