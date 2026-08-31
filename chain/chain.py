"""
Phase 7: 合意 — 「どの履歴が正か」を、投票なしで決める

なぜ必要か
----------
ここまでの部品は全部「ローカルで検証できるもの」だった。
残った唯一の難問は、valid な履歴が 2 本あったときにどちらを選ぶか。

Bitcoin の答えは驚くほど素朴。

    **積み上がった仕事量 (PoW) が最も大きい枝を正とする。**

多数決ではない。ノードの数を数えると、なりすまし（Sybil 攻撃）で
いくらでも票を増やせてしまう。仕事量なら増やすのに実費がかかる。
「1 CPU = 1 票」ではなく「1 ハッシュ = 1 票」であることが要点。

この規則の直接の帰結が 2 つある。

    - 分岐は正常な出来事であって、事故ではない（伝播遅延で普通に起きる）
    - **確定は確率的**。どれだけ深く埋まっても、より長い枝が現れれば覆る

到達点
------
- 分岐 → リオーグ（tip の載せ替え）が実際に起きるのを見る
- 【本題】3 ブロック確認済みの支払いが、後から現れた長い枝で消えるのを見る
  = 51% 攻撃 / 二重支払いの実演
- 何回確認すれば安全かを、中本論文の式で数字にする
"""

from __future__ import annotations

import math
import time
from dataclasses import dataclass

import block as blockmod
from block import Block, GENESIS_PREV
from tx import InvalidTx, Tx, UTXOSet, Wallet, coinbase


REWARD = 50


@dataclass
class AddResult:
    status: str          # "extend" | "fork" | "reorg"
    depth: int           # 新しい tip の高さ
    detached: int = 0    # リオーグで巻き戻されたブロック数


class Blockchain:
    """ブロックの DAG を保持し、最大仕事量の枝を tip として選ぶ。

    実装方針: UTXO 集合は保存せず、必要になるたび genesis から再生する。
    実用チェーンでは論外に遅いが、ここでは「状態はチェーンから導出される」
    という関係が一切ごまかしなく見えることを優先した。
    """

    def __init__(self, difficulty: int = 16) -> None:
        self.difficulty = difficulty
        self.blocks: dict[bytes, Block] = {}
        self.work: dict[bytes, int] = {}          # 累積仕事量
        self.tip: bytes | None = None

    # ------------------------------------------------------------ 参照

    def height(self, h: bytes | None = None) -> int:
        h = h or self.tip
        return len(self.branch(h)) - 1            # genesis を 0 とする

    def branch(self, h: bytes | None = None) -> list[Block]:
        """genesis から h までの一本道を返す。"""
        h = h or self.tip
        out: list[Block] = []
        while h in self.blocks:
            blk = self.blocks[h]
            out.append(blk)
            h = blk.header.prev_hash
        return list(reversed(out))

    def utxo_for(self, h: bytes | None = None) -> UTXOSet:
        """その枝を genesis から再生して得られる UTXO 集合。"""
        utxos = UTXOSet()
        for blk in self.branch(h):
            for t in blk.txs:
                utxos.apply(t)
        return utxos

    @property
    def utxos(self) -> UTXOSet:
        return self.utxo_for(self.tip)

    def contains_tx(self, txid: bytes, h: bytes | None = None) -> bool:
        return any(t.txid() == txid for blk in self.branch(h) for t in blk.txs)

    # ------------------------------------------------------------ 検証

    def validate(self, blk: Block) -> None:
        """ブロック単体 + 親の状態に対して検証する。落ちれば InvalidTx。"""
        if not blk.header.is_valid_pow():
            raise InvalidTx("PoW を満たしていない")
        if blk.header.difficulty < self.difficulty:
            raise InvalidTx("難易度が規定を下回る")
        if not blk.merkle_ok():
            raise InvalidTx("マークル根が中身と一致しない")
        if not blk.txs:
            raise InvalidTx("tx が空")
        if not blk.txs[0].is_coinbase():
            raise InvalidTx("先頭が coinbase でない")
        if any(t.is_coinbase() for t in blk.txs[1:]):
            raise InvalidTx("coinbase が 2 つ以上ある")

        prev = blk.header.prev_hash
        if prev != GENESIS_PREV and prev not in self.blocks:
            raise InvalidTx("親ブロックを知らない")

        # 親の時点の状態を作って、そこに tx を順に当てていく
        utxos = self.utxo_for(prev) if prev != GENESIS_PREV else UTXOSet()
        fees = 0
        for t in blk.txs[1:]:
            fees += utxos.validate(t)
            utxos.apply(t)

        # coinbase は「新規発行 + 手数料」を超えて作れない
        utxos.validate(blk.txs[0], coinbase_reward=REWARD + fees)

    # ------------------------------------------------------------ 追加

    def add(self, blk: Block) -> AddResult:
        """検証して取り込み、必要なら tip を載せ替える。"""
        self.validate(blk)

        h = blk.hash()
        prev = blk.header.prev_hash
        parent_work = self.work.get(prev, 0)
        self.blocks[h] = blk
        self.work[h] = parent_work + 2 ** blk.header.difficulty

        if self.tip is None:
            self.tip = h
            return AddResult("extend", self.height(h))

        if self.work[h] > self.work[self.tip]:
            old_branch = {b.hash() for b in self.branch(self.tip)}
            new_branch = self.branch(h)
            detached = len(old_branch - {b.hash() for b in new_branch})
            status = "extend" if prev == self.tip else "reorg"
            self.tip = h
            return AddResult(status, self.height(h), detached)

        # 仕事量が足りない枝。保持はするが tip は動かさない
        return AddResult("fork", self.height(self.tip))

    def mine_block(self, miner: Wallet, txs: list[Tx] | None = None,
                   on: bytes | None = None,
                   difficulty: int | None = None) -> Block:
        """on の上に 1 ブロック掘る（on 省略時は現 tip）。

        coinbase には高さと親を混ぜて一意性を確保する。
        """
        parent = self.tip if on is None else on
        prev_hash = parent if parent is not None else GENESIS_PREV
        body = list(txs or [])

        utxos = self.utxo_for(parent) if parent else UTXOSet()
        fees = sum(utxos.validate(t) for t in body)
        tag = prev_hash[:8] + len(self.blocks).to_bytes(4, "big") + \
            int(time.time_ns()).to_bytes(8, "big")
        cb = coinbase(miner.address, REWARD + fees, tag=tag)

        candidate = blockmod.build(prev_hash, [cb] + body,
                                   difficulty or self.difficulty)
        mined, _ = blockmod.mine(candidate)
        return mined


# ---------------------------------------------------------------- 確認回数

def attacker_success_probability(q: float, z: int) -> float:
    """攻撃者のハッシュ力割合 q のとき、z 確認を覆せる確率。

    中本論文 (2008) 第 11 節の式。攻撃者が z ブロック遅れから追いつく
    確率をポアソン分布 + ギャンブラーの破産問題で評価している。

        λ = z * q / p
        P = 1 - Σ_{k=0}^{z} (λ^k e^{-λ} / k!) * (1 - (q/p)^(z-k))

    q >= 0.5 のとき、追いつく確率は 1（いつかは必ず追い越す）。
    「51%」という数字の出どころはここ。
    """
    p = 1.0 - q
    if q >= p:
        return 1.0
    lam = z * (q / p)
    total = 0.0
    for k in range(z + 1):
        poisson = math.exp(-lam) * lam ** k / math.factorial(k)
        total += poisson * (1 - (q / p) ** (z - k))
    return 1 - total


# ---------------------------------------------------------------- 自己確認

def self_check() -> None:
    miner, alice = Wallet("miner"), Wallet("alice")
    bc = Blockchain(difficulty=10)

    g = bc.mine_block(miner)
    assert bc.add(g).status == "extend"
    assert bc.height() == 0
    assert miner.balance(bc.utxos) == REWARD

    b1 = bc.mine_block(miner)
    assert bc.add(b1).status == "extend"
    assert bc.height() == 1
    assert miner.balance(bc.utxos) == 2 * REWARD

    # tx 入りブロック
    from tx import transfer
    t = transfer(miner, bc.utxos, alice.address, 20, fee=2)
    b2 = bc.mine_block(miner, [t])
    assert bc.add(b2).status == "extend"
    assert alice.balance(bc.utxos) == 20
    # 手数料 2 が coinbase に乗っている
    assert bc.blocks[bc.tip].txs[0].total_out() == REWARD + 2

    # 不正なブロックは弾かれる
    from dataclasses import replace as dc_replace
    bad = bc.mine_block(miner)
    bad = dc_replace(bad, header=dc_replace(bad.header, nonce=bad.header.nonce + 1))
    try:
        bc.add(bad)
        raise AssertionError("PoW 不正が通った")
    except InvalidTx:
        pass

    # 分岐: 同じ親から 2 本目を掘っても tip は動かない
    side = bc.mine_block(miner, on=bc.blocks[bc.tip].header.prev_hash)
    before = bc.tip
    assert bc.add(side).status == "fork"
    assert bc.tip == before

    # その枝を伸ばすとリオーグ
    side2 = bc.mine_block(miner, on=side.hash())
    res = bc.add(side2)
    assert res.status == "reorg", res.status
    assert bc.tip == side2.hash()

    # 確認回数の式
    assert attacker_success_probability(0.5, 10) == 1.0
    assert attacker_success_probability(0.1, 0) == 1.0
    assert attacker_success_probability(0.1, 6) < 0.001

    print("  [ok] chain.py 自己確認 通過")


def demo() -> None:
    from tx import addr_str, transfer

    honest, alice, merchant = Wallet("HonestMiner"), Wallet("Alice"), Wallet("Merchant")
    bc = Blockchain(difficulty=14)

    print("\n-- 観察 1: チェーンを伸ばす ------------------------------------")
    g = bc.mine_block(honest)
    bc.add(g)
    # Alice に元手を渡しておく
    seed = transfer(honest, bc.utxos, alice.address, 50)
    bc.add(bc.mine_block(honest, [seed]))
    print(f"    高さ {bc.height()}  tip = {bc.tip[:8].hex()}  "
          f"累積仕事量 = {bc.work[bc.tip]:,}")
    print(f"    Alice 残高 = {alice.balance(bc.utxos)}")

    print("\n-- 観察 2: Alice が商品を買い、3 確認まで待つ ------------------")
    payment = transfer(alice, bc.utxos, merchant.address, 50)
    bc.add(bc.mine_block(honest, [payment]))
    payment_block = bc.tip
    print(f"    支払い tx {payment.txid()[:8].hex()} を高さ {bc.height()} に取り込み")
    for _ in range(2):
        bc.add(bc.mine_block(honest))
    print(f"    さらに 2 ブロック採掘 → 高さ {bc.height()}（3 確認）")
    print(f"    Merchant 残高 = {merchant.balance(bc.utxos)}  ← 入金を確認、商品を発送")
    print(f"    Alice 残高    = {alice.balance(bc.utxos)}")
    honest_tip, honest_work = bc.tip, bc.work[bc.tip]

    print("\n-- 観察 3【本題】攻撃者が裏で長い枝を掘っていた ----------------")
    print("    Alice は支払い tx を含めず、同じ 50 を自分に送る枝を")
    print("    支払いブロックの『ひとつ手前』から秘密裏に伸ばしていた。")
    fork_point = bc.blocks[payment_block].header.prev_hash
    self_pay = transfer(alice, bc.utxo_for(fork_point), alice.address, 50)
    print(f"      競合 tx {self_pay.txid()[:8].hex()} … 同じ UTXO を Alice 自身へ")

    attack_tip = fork_point
    for i in range(4):
        blk = bc.mine_block(alice, [self_pay] if i == 0 else [], on=attack_tip)
        res = bc.add(blk)
        attack_tip = blk.hash()
        mark = "  ← 公開した瞬間に tip が載せ替わる" if res.status == "reorg" else ""
        print(f"      攻撃枝 +{i + 1} → status={res.status:<6} "
              f"仕事量 {bc.work[attack_tip]:>12,} vs 正直枝 {honest_work:>12,}{mark}")

    print(f"\n    tip は攻撃枝か? {bc.tip == attack_tip}")
    print(f"    支払い tx は今のチェーンに残っているか? "
          f"{bc.contains_tx(payment.txid())}")
    print(f"    Merchant 残高 = {merchant.balance(bc.utxos)}   ← 商品は渡した後で消えた")
    print(f"    Alice 残高    = {alice.balance(bc.utxos)}   ← 50 は手元に戻っている")
    print(f"    正直枝 {honest_tip[:8].hex()} のブロックは消えていない: "
          f"{honest_tip in bc.blocks}（ただし tip ではない = 孤児）")
    print("""
    → ブロックは 1 つも壊れていない。署名も PoW も全部 valid のまま。
      「どちらの枝を見るか」が変わっただけで、確定していたはずの支払いが消えた。

    → これが二重支払い攻撃の本体。必要なのは正直者より速く掘り続ける力だけで、
      暗号を破る必要はまったくない。""")

    print("\n-- 観察 4: では何確認待てばいいのか ----------------------------")
    print("    中本論文の式で、攻撃者のハッシュ力 q に対する逆転確率を出す。")
    qs = [0.05, 0.10, 0.25, 0.35, 0.45]
    print(f"\n    {'確認数 z':>8}" + "".join(f"{f'q={q:.0%}':>12}" for q in qs))
    print("    " + "-" * (8 + 12 * len(qs)))
    for z in (0, 1, 2, 3, 6, 12, 24):
        row = "".join(f"{attacker_success_probability(q, z):>12.2e}" for q in qs)
        print(f"    {z:>8}{row}")
    print("""
    → z = 0（未確認）では、どんな弱い攻撃者でも成功率 100%。
      ゼロ確認の支払いを受け取ってはいけない理由がこれ。

    → q = 10% なら 6 確認で 10^-4 台。Bitcoin が「6 confirmations」を
      慣習にしているのはこのあたりが根拠。ただし高額なら深く待つ。

    → q が 45% に近づくと、確認をいくら重ねても確率が落ちない。
      50% を超えた瞬間に成功率は厳密に 1 になる。これが 51% 攻撃。

    → 重要な帰結: ブロックチェーンに「確定」はない。あるのは
      「覆すのに必要な費用」だけ。安全性とは経済的な非現実性のこと。
""")


if __name__ == "__main__":
    from util import enable_utf8_stdout

    enable_utf8_stdout()
    self_check()
    demo()
