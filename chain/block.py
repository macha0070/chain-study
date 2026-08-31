"""
Phase 6: ブロック — 順序を固定するための箱

なぜ必要か
----------
Phase 5 までで「正しい tx かどうか」は判定できるようになった。
しかし決定的に足りないものが 1 つある。**順序**。

    Alice が同じ UTXO を Bob と Carol に同時に送ったとする。
    tx はどちらも単体では完全に valid。先に見たほうを正とするなら、
    ノードごとに答えが変わる。ネットワークが分裂する。

だから「みんなが同じ順序を見る」仕組みが要る。それがブロックで、
ブロックは 2 つの道具で順序を固定する。

    1. prev_hash    直前のブロックを指す。並べ替えると全部のハッシュが壊れる
    2. PoW          ブロックを 1 つ作るのに実費（計算）がかかる
                    → 履歴を書き換えるには、その先の全ブロックを作り直す必要がある

ヘッダは小さく保つ。中身（tx の山）はマークル根 32 バイトに要約して
ヘッダに入れるだけ。マイナーが延々ハッシュするのはこのヘッダだけで済む。

到達点
------
- ヘッダを 1 ビット変えると PoW が即座に無効になることを確認する
- 難易度を上げるとマイニング時間が指数的に伸びることを実測する
"""

from __future__ import annotations

import time
from dataclasses import dataclass, replace

from hashing import H, meets_difficulty
from merkle import merkle_root
from tx import Tx


GENESIS_PREV = bytes(32)


@dataclass(frozen=True)
class BlockHeader:
    """マイナーがハッシュし続ける対象。中身の tx はここには入らない。"""
    prev_hash: bytes
    merkle_root: bytes
    timestamp: int
    difficulty: int          # 先頭に要求する 0 ビット数
    nonce: int

    def to_bytes(self) -> bytes:
        return (self.prev_hash
                + self.merkle_root
                + self.timestamp.to_bytes(8, "big")
                + self.difficulty.to_bytes(4, "big")
                + self.nonce.to_bytes(8, "big"))

    def hash(self) -> bytes:
        return H(self.to_bytes())

    def is_valid_pow(self) -> bool:
        return meets_difficulty(self.hash(), self.difficulty)


@dataclass(frozen=True)
class Block:
    header: BlockHeader
    txs: tuple[Tx, ...]

    def hash(self) -> bytes:
        return self.header.hash()

    def merkle_ok(self) -> bool:
        """ヘッダの根が、実際に入っている tx から作れる根と一致するか。

        ここが一致していれば、ヘッダ 32 バイトを守るだけで全 tx が守られる。
        """
        return self.header.merkle_root == merkle_root([t.txid() for t in self.txs])

    def coinbase_tx(self) -> Tx:
        return self.txs[0]

    def __repr__(self) -> str:
        return (f"Block({self.hash()[:6].hex()} prev={self.header.prev_hash[:6].hex()} "
                f"d={self.header.difficulty} tx={len(self.txs)})")


def build(prev_hash: bytes, txs: list[Tx], difficulty: int,
          timestamp: int | None = None) -> Block:
    """未採掘のブロックを組み立てる（nonce = 0）。"""
    header = BlockHeader(
        prev_hash=prev_hash,
        merkle_root=merkle_root([t.txid() for t in txs]),
        timestamp=timestamp if timestamp is not None else int(time.time()),
        difficulty=difficulty,
        nonce=0,
    )
    return Block(header, tuple(txs))


def mine(block: Block, max_tries: int = 1 << 40) -> tuple[Block, int]:
    """PoW を満たす nonce を探す。

    やっていることは Phase 1 の mine() と同一。
    「当たりが出るまでヘッダの nonce を回してハッシュする」だけ。
    賢い方法が存在しないことが、そのまま『仕事の証明』の根拠になる。

    Returns: (採掘済みブロック, 試行回数)
    """
    header = block.header
    for tries in range(1, max_tries + 1):
        candidate = replace(header, nonce=tries - 1)
        if meets_difficulty(candidate.hash(), candidate.difficulty):
            return replace(block, header=candidate), tries
    raise RuntimeError("nonce が見つからなかった")


# ---------------------------------------------------------------- 自己確認

def self_check() -> None:
    from tx import Wallet, coinbase

    w = Wallet("miner")
    cb = coinbase(w.address, 50, tag=b"h1")
    blk = build(GENESIS_PREV, [cb], difficulty=8)

    assert blk.merkle_ok()
    mined, tries = mine(blk)
    assert mined.header.is_valid_pow()
    assert mined.merkle_ok()
    assert tries >= 1

    # ヘッダを 1 ビットでも動かすと PoW が壊れる
    broken = replace(mined, header=replace(mined.header, timestamp=mined.header.timestamp + 1))
    assert not broken.header.is_valid_pow()

    # tx を差し替えるとマークル根が合わなくなる
    other = coinbase(Wallet("thief").address, 50, tag=b"h1")
    swapped = replace(mined, txs=(other,))
    assert not swapped.merkle_ok()

    print("  [ok] block.py 自己確認 通過")


def demo() -> None:
    from tx import Wallet, coinbase

    miner = Wallet("Miner")

    print("\n-- 観察 1: ブロックを 1 つ掘る ---------------------------------")
    cb = coinbase(miner.address, 50, tag=b"height-1")
    blk = build(GENESIS_PREV, [cb], difficulty=18)
    t0 = time.perf_counter()
    mined, tries = mine(blk)
    dt = time.perf_counter() - t0
    h = mined.header
    print(f"    prev_hash   = {h.prev_hash.hex()}")
    print(f"    merkle_root = {h.merkle_root.hex()}")
    print(f"    difficulty  = {h.difficulty}   (先頭 {h.difficulty} ビットが 0)")
    print(f"    nonce       = {h.nonce:,}   ({tries:,} 回試行 / {dt:.2f} 秒)")
    print(f"    ヘッダ長    = {len(h.to_bytes())} バイト")
    print(f"    block hash  = {mined.hash().hex()}")
    print(f"    PoW 有効?   = {h.is_valid_pow()}")

    print("\n-- 観察 2: ヘッダを 1 ビット動かすと即無効 ---------------------")
    for label, tweak in [
        ("timestamp を +1", replace(h, timestamp=h.timestamp + 1)),
        ("nonce を +1", replace(h, nonce=h.nonce + 1)),
        ("merkle_root を 1 バイト変更",
         replace(h, merkle_root=bytes([h.merkle_root[0] ^ 1]) + h.merkle_root[1:])),
    ]:
        print(f"    {label:<28} → PoW 有効? {tweak.is_valid_pow()}")
    print("    → 一度掘ったブロックは『中身を固定した状態でしか有効でない』。")
    print("      書き換えたければ、同じだけの計算をもう一度払うしかない。")

    print("\n-- 観察 3: 難易度とマイニング時間 ------------------------------")
    print(f"    {'難易度 d':>9} {'試行回数':>12} {'秒':>8} {'期待 2^d':>12}")
    print("    " + "-" * 44)
    for d in (8, 12, 16, 19, 21):
        b = build(GENESIS_PREV, [coinbase(miner.address, 50, tag=f"d{d}".encode())], d)
        t0 = time.perf_counter()
        _, tries = mine(b)
        print(f"    {d:>9} {tries:>12,} {time.perf_counter() - t0:>8.2f} {2**d:>12,}")
    print("""
    → Bitcoin の実際の難易度はおよそ 2^76 に相当する。
      家庭用 PC の毎秒 100 万ハッシュでは、1 ブロックに宇宙年齢を超える時間がかかる。
      それを 10 分に縮めているのが、地球全体の専用 ASIC の総力。

    → 逆に言えば、この学習用チェーンで d=20 が数秒で掘れるということは、
      「d が小さいチェーンは安い」ということでもある。安全性 = 積み上げた仕事量。
""")


if __name__ == "__main__":
    from util import enable_utf8_stdout

    enable_utf8_stdout()
    self_check()
    demo()
