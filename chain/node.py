"""
Phase 8: P2P ノードとネットワーク — 分岐は事故ではなく通常運転

なぜ必要か
----------
Phase 7 までは `Blockchain` オブジェクトが 1 つしかなかった。
分岐は「こちらが意図して作った」ものであって、自然に発生したものではない。

しかし現実のブロックチェーンでは、誰も攻撃していなくても分岐は起きる。
理由はただひとつ、**光の速さが有限だから**。

    ノード A がブロックを見つける
      → 全ノードに届くまで Δ 秒かかる
      → その Δ 秒のあいだ、ノード B は古い tip の上を掘り続けている
      → B が当ててしまったら、その瞬間に枝が 2 本になる

つまり分岐率は「伝播遅延 / ブロック生成間隔」でおおよそ決まる。
Bitcoin がブロック間隔を 10 分という長さに置いているのは、
数秒の伝播遅延を無視できるようにするため。逆に間隔を詰めると孤児が増え、
実効的なセキュリティ（正直者の仕事が無駄になる割合）が落ちる。

モデル化の方針（重要）
----------------------
ここでは **PoW は本物、スケジューリングは模擬** という割り切りをしている。

    - ブロックは実際に nonce を探して掘る（PoW は一切ごまかさない）
    - 「次に誰が当てるか」は、ハッシュ力を重みにした抽選で決める
    - 「いつ当たるか」は、指数分布からの乱数で決める

本当に全ノードを並列に走らせて競争させることもできるが、それをやると
観測したい統計（孤児率と遅延の関係）を得るのに実時間が必要になる。
PoW の当選過程はポアソン過程なので、上の模擬は統計的に等価。
この割り切りを明示しておくのは、結果を読むときに嘘をつかないため。

到達点
------
- 遅延 0 では分岐がほぼ起きない
- 遅延をブロック間隔の 10% まで上げると孤児率が目に見えて上がる
- 遅延と孤児率の関係を数字の表にできる
"""

from __future__ import annotations

import heapq
import itertools
import random
from dataclasses import dataclass, field

from block import Block
from chain import REWARD, AddResult, Blockchain
from tx import InvalidTx, Tx, UTXOSet, Wallet


# ---------------------------------------------------------------- メッセージ

@dataclass(order=True)
class Envelope:
    """ネットワークを流れる 1 通。deliver_at の順に配送される。"""
    deliver_at: float
    seq: int                                  # 同時刻の順序を決める通し番号
    to_node: int = field(compare=False)
    from_node: int = field(compare=False)
    kind: str = field(compare=False)          # "block" | "tx"
    payload: object = field(compare=False)


# ---------------------------------------------------------------- ノード

class Node:
    """1 台のフルノード。自分の視点のチェーンと mempool だけを持つ。

    重要なのは「ノードは自分が見たものしか知らない」という点。
    グローバルな真実を参照してよいのはシミュレータ側だけで、
    ノードの判断は必ず自分の `chain` と `mempool` だけを根拠にする。
    """

    def __init__(self, node_id: int, name: str, difficulty: int,
                 hashrate: float = 1.0) -> None:
        self.id = node_id
        self.name = name
        self.hashrate = hashrate
        self.wallet = Wallet(name)
        self.chain = Blockchain(difficulty)
        self.mempool: dict[bytes, Tx] = {}
        self.orphan_pool: dict[bytes, list[Block]] = {}   # 親待ちのブロック
        self.mined = 0

    # ------------------------------------------------------------ 受信

    def receive_block(self, blk: Block) -> AddResult | None:
        """ブロックを受け取る。親が未着なら保留する。

        保留 (orphan pool) が要るのは、ネットワークが順序を保証しないから。
        子が先に着いたら親を待ち、親が着いた時点で再投入する。
        """
        h = blk.hash()
        if h in self.chain.blocks:
            return None                                    # 既知

        try:
            result = self.chain.add(blk)
        except InvalidTx as e:
            if "親ブロックを知らない" in str(e):
                self.orphan_pool.setdefault(blk.header.prev_hash, []).append(blk)
                return None
            return None                                    # 本当に不正 → 捨てる

        # この親を待っていた子がいれば連鎖的に取り込む
        for child in self.orphan_pool.pop(h, []):
            self.receive_block(child)

        self._resync_mempool()
        return result

    def receive_tx(self, t: Tx) -> bool:
        txid = t.txid()
        if txid in self.mempool or self.chain.contains_tx(txid):
            return False
        self.mempool[txid] = t
        return True

    # ------------------------------------------------------------ mempool

    def _resync_mempool(self) -> None:
        """tip が動いたあと mempool を作り直す。

        リオーグで巻き戻されたブロックに入っていた tx は、
        「無かったこと」になるので mempool に戻さないといけない。
        戻し忘れると送金が静かに消える。実装で最も間違えやすい箇所。
        """
        canonical = {t.txid() for blk in self.chain.branch() for t in blk.txs}

        candidates: dict[bytes, Tx] = dict(self.mempool)
        for blk in self.chain.blocks.values():             # 孤児ブロックも含む
            for t in blk.txs[1:]:                          # coinbase は戻さない
                if t.txid() not in canonical:
                    candidates[t.txid()] = t

        utxos = self.chain.utxos
        kept: dict[bytes, Tx] = {}
        for txid, t in candidates.items():
            if txid in canonical:
                continue
            try:
                utxos.validate(t)                          # 現 tip で成立するか
            except InvalidTx:
                continue
            kept[txid] = t
        self.mempool = kept

    def select_txs(self, limit: int = 8) -> list[Tx]:
        """mempool から、この tip の上で同時に成立する tx を選ぶ。

        手数料の高い順に取る（実際のマイナーと同じ動機）。
        1 つ取り込むたびに UTXO を進めるので、競合する tx は自動的に落ちる。
        """
        utxos: UTXOSet = self.chain.utxos
        scored: list[tuple[int, bytes, Tx]] = []
        for txid, t in self.mempool.items():
            try:
                scored.append((utxos.validate(t), txid, t))
            except InvalidTx:
                continue
        scored.sort(key=lambda x: -x[0])

        picked: list[Tx] = []
        working = utxos.copy()
        for _, _, t in scored[:limit]:
            try:
                working.validate(t)
            except InvalidTx:
                continue
            working.apply(t)
            picked.append(t)
        return picked

    # ------------------------------------------------------------ 採掘

    def mine(self) -> Block:
        """自分の視点の tip の上に 1 ブロック掘る。"""
        blk = self.chain.mine_block(self.wallet, self.select_txs())
        self.mined += 1
        return blk

    # ------------------------------------------------------------ 表示

    def view(self) -> dict:
        tip = self.chain.tip
        return {
            "id": self.id,
            "name": self.name,
            "hashrate": self.hashrate,
            "height": self.chain.height() if tip else -1,
            "tip": tip.hex() if tip else None,
            "work": self.chain.work.get(tip, 0) if tip else 0,
            "known_blocks": len(self.chain.blocks),
            "mempool": len(self.mempool),
            "orphan_pool": sum(len(v) for v in self.orphan_pool.values()),
            "mined": self.mined,
            "balance": self.wallet.balance(self.chain.utxos) if tip else 0,
        }


# ---------------------------------------------------------------- ネットワーク

class Network:
    """複数ノードと、遅延つきの配送キュー。

    シミュレータ時刻 `now`（秒）を進めながら、
    「配送 → 採掘 → 伝播」を繰り返す。
    """

    def __init__(self, node_count: int = 4, difficulty: int = 14,
                 latency: float = 2.0, block_interval: float = 30.0,
                 hashrates: list[float] | None = None,
                 seed: int | None = 20260901) -> None:
        self.difficulty = difficulty
        self.latency = latency
        self.block_interval = block_interval
        self.rng = random.Random(seed)
        self.now = 0.0
        self.queue: list[Envelope] = []
        self._seq = itertools.count()
        self.log: list[dict] = []

        names = [f"Node {chr(ord('A') + i)}" for i in range(node_count)]
        rates = hashrates or [1.0] * node_count
        self.nodes = [Node(i, names[i], difficulty, rates[i])
                      for i in range(node_count)]

        self.wallets: dict[str, Wallet] = {}
        self._genesis()

    # ------------------------------------------------------------ 初期化

    def _genesis(self) -> None:
        """全ノードが同じ genesis を共有した状態から始める。"""
        founder = self.nodes[0]
        g = founder.chain.mine_block(founder.wallet)
        for n in self.nodes:
            n.chain.add(g)
        self.genesis = g.hash()
        self._emit("genesis", f"genesis {g.hash()[:8].hex()} を全ノードで共有")

    def wallet(self, name: str) -> Wallet:
        """名前つきウォレット（UI から使う）。無ければ作る。"""
        if name not in self.wallets:
            self.wallets[name] = Wallet(name)
        return self.wallets[name]

    # ------------------------------------------------------------ 配送

    def _emit(self, kind: str, text: str, **extra) -> dict:
        entry = {"t": round(self.now, 2), "kind": kind, "text": text, **extra}
        self.log.append(entry)
        del self.log[:-400]                    # 直近だけ保持
        return entry

    def _send(self, from_node: int, kind: str, payload: object) -> None:
        """全ピアへ配る。到達時刻は latency にゆらぎを乗せる。"""
        for n in self.nodes:
            if n.id == from_node:
                continue
            jitter = self.rng.uniform(0.5, 1.5) if self.latency > 0 else 0.0
            heapq.heappush(self.queue, Envelope(
                deliver_at=self.now + self.latency * jitter,
                seq=next(self._seq),
                to_node=n.id, from_node=from_node, kind=kind, payload=payload))

    def deliver_until(self, t: float) -> int:
        """時刻 t までに届くはずのメッセージを配送する。"""
        delivered = 0
        while self.queue and self.queue[0].deliver_at <= t:
            env = heapq.heappop(self.queue)
            node = self.nodes[env.to_node]
            if env.kind == "block":
                res = node.receive_block(env.payload)
                if res and res.status == "reorg":
                    self._emit("reorg",
                               f"{node.name} がリオーグ: {res.detached} ブロックを巻き戻し "
                               f"→ 高さ {res.depth}")
            else:
                node.receive_tx(env.payload)
            delivered += 1
        return delivered

    # ------------------------------------------------------------ 操作

    def submit_tx(self, t: Tx, origin: int = 0) -> None:
        self.nodes[origin].receive_tx(t)
        self._send(origin, "tx", t)
        self._emit("tx", f"tx {t.txid()[:8].hex()} を {self.nodes[origin].name} に投入")

    def mine_next(self) -> dict:
        """次の 1 ブロックを進める。

        1. 指数分布で「次に誰かが当てるまでの時間」を引く
        2. その時刻までに届くメッセージを配送する（← ここが分岐の分かれ目）
        3. ハッシュ力の重みで当選者を選び、その視点の tip の上に本当に掘る
        4. 伝播させる
        """
        dt = self.rng.expovariate(1.0 / self.block_interval)
        self.now += dt
        self.deliver_until(self.now)

        winner = self.rng.choices(self.nodes,
                                  weights=[n.hashrate for n in self.nodes])[0]
        parent_before = winner.chain.tip
        blk = winner.mine()
        res = winner.chain.add(blk)
        winner._resync_mempool()
        self._send(winner.id, "block", blk)

        forked = parent_before != blk.header.prev_hash or self._is_fork(blk)
        entry = self._emit(
            "block",
            f"{winner.name} が高さ {winner.chain.height()} を採掘 "
            f"({blk.hash()[:8].hex()}, tx {len(blk.txs)} 件)"
            + ("  ← 古い tip の上（分岐発生）" if forked else ""),
            node=winner.id, block=blk.hash().hex(), forked=forked)
        entry["status"] = res.status
        return entry

    def _is_fork(self, blk: Block) -> bool:
        """この親からすでに別の子が出ていたか（= 分岐したか）。"""
        prev = blk.header.prev_hash
        siblings = [b for n in self.nodes for b in n.chain.blocks.values()
                    if b.header.prev_hash == prev and b.hash() != blk.hash()]
        return bool(siblings)

    def run(self, blocks: int = 10) -> list[dict]:
        return [self.mine_next() for _ in range(blocks)]

    def settle(self) -> None:
        """キューに残った全メッセージを配送し切る（ネットワークを落ち着かせる）。"""
        if self.queue:
            self.deliver_until(self.queue[-1].deliver_at + self.latency * 2 + 1)

    # ------------------------------------------------------------ 統計

    def all_blocks(self) -> dict[bytes, Block]:
        """どこかのノードが知っているブロック全部（観測者の視点）。"""
        out: dict[bytes, Block] = {}
        for n in self.nodes:
            out.update(n.chain.blocks)
        return out

    def canonical_hashes(self, observer: int = 0) -> set[bytes]:
        return {b.hash() for b in self.nodes[observer].chain.branch()}

    def stats(self, observer: int = 0) -> dict:
        total = len(self.all_blocks())
        canonical = len(self.canonical_hashes(observer))
        orphans = total - canonical
        tips = {n.chain.tip for n in self.nodes}
        return {
            "time": round(self.now, 2),
            "total_blocks": total,
            "canonical": canonical,
            "orphans": orphans,
            "orphan_rate": orphans / total if total else 0.0,
            "converged": len(tips) == 1,
            "in_flight": len(self.queue),
        }


# ---------------------------------------------------------------- 自己確認

def self_check() -> None:
    net = Network(node_count=3, difficulty=8, latency=0.0,
                  block_interval=30.0, seed=1)
    assert all(n.chain.tip == net.genesis for n in net.nodes)

    net.run(6)
    net.settle()
    st = net.stats()
    assert st["total_blocks"] == 7                    # genesis + 6
    assert st["converged"], "遅延 0 なのに収束していない"
    assert st["orphans"] == 0, "遅延 0 で孤児が出た"

    # 遅延が大きいと分岐が起きる
    slow = Network(node_count=4, difficulty=8, latency=25.0,
                   block_interval=30.0, seed=7)
    slow.run(25)
    slow.settle()
    assert slow.stats()["orphans"] > 0, "高遅延なのに孤児が 0"

    # 送金がネットワーク越しに通る
    net2 = Network(node_count=3, difficulty=8, latency=1.0, seed=3)
    net2.run(3)
    net2.settle()
    miner = max(net2.nodes, key=lambda n: n.mined)
    bob = net2.wallet("bob")
    from tx import transfer
    t = transfer(miner.wallet, miner.chain.utxos, bob.address, 10, fee=1)
    net2.submit_tx(t, origin=miner.id)
    assert len(miner.mempool) == 1
    for _ in range(6):
        net2.mine_next()
    net2.settle()
    assert net2.nodes[0].chain.contains_tx(t.txid()), "送金が取り込まれなかった"
    assert bob.balance(net2.nodes[0].chain.utxos) == 10

    print("  [ok] node.py 自己確認 通過")


def demo() -> None:
    print("\n-- 観察 1: 遅延 0 なら分岐しない -------------------------------")
    net = Network(node_count=4, difficulty=12, latency=0.0,
                  block_interval=30.0, seed=42)
    net.run(20)
    net.settle()
    st = net.stats()
    print(f"    ブロック {st['total_blocks']} 個 / 孤児 {st['orphans']} 個 "
          f"/ 全ノード一致 = {st['converged']}")
    print("    → 誰かが掘った瞬間に全員が知るので、古い tip の上を掘る者がいない。")

    print("\n-- 観察 2: 遅延を上げると孤児が増える -------------------------")
    print("    ブロック間隔 30 秒に対して、伝播遅延を変えながら 60 ブロック走らせる。")
    print(f"\n    {'遅延/間隔':>10} {'遅延(秒)':>10} {'孤児':>6} {'総数':>6} {'孤児率':>9}")
    print("    " + "-" * 46)
    for ratio in (0.0, 0.02, 0.05, 0.10, 0.25, 0.50, 1.00):
        n = Network(node_count=6, difficulty=10, latency=30.0 * ratio,
                    block_interval=30.0, seed=1234)
        n.run(60)
        n.settle()
        s = n.stats()
        print(f"    {ratio:>10.0%} {30.0 * ratio:>10.1f} {s['orphans']:>6} "
              f"{s['total_blocks']:>6} {s['orphan_rate']:>9.1%}")
    print("""
    → 孤児率はおおよそ「遅延 / ブロック間隔」に比例して増える。
      孤児になったブロックの仕事は、チェーンの安全性に一切寄与しない。
      つまり遅延はそのままセキュリティの目減りになる。

    → Bitcoin がブロック間隔を 10 分にしている理由がこれ。
      伝播が数秒なら比は 1% 以下で、孤児は無視できる。
      「もっと速くすればいいのに」が素朴には成り立たない。

    → 逆に言えば、伝播を速くできれば間隔は詰められる。
      Compact Blocks や FIBRE のような伝播最適化はそこを狙っている。
""")

    print("-- 観察 3: 分岐から収束するまでを追う --------------------------")
    net3 = Network(node_count=4, difficulty=12, latency=20.0,
                   block_interval=30.0, seed=99)
    net3.run(12)
    net3.settle()
    for entry in net3.log[-14:]:
        mark = {"block": "  ", "reorg": "!!", "tx": "  ", "genesis": "  "}[entry["kind"]]
        print(f"    [{entry['t']:>7.1f}s] {mark} {entry['text']}")
    s = net3.stats()
    print(f"\n    最終: 高さ {net3.nodes[0].chain.height()} / 孤児 {s['orphans']} / "
          f"全ノード一致 = {s['converged']}")
    print("""
    → リオーグは異常ではない。遅延がある限り必ず起きる通常動作。
      「1 確認では足りない」という話は、攻撃者がいなくても成り立つ。
""")


if __name__ == "__main__":
    from util import enable_utf8_stdout

    enable_utf8_stdout()
    self_check()
    demo()
