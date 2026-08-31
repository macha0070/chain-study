"""
攻撃シナリオ — 手順を engine 側に置く

なぜここに置くか
----------------
二重支払い攻撃は「UI の機能」ではなく「チェーンの性質」の実演。
Web サーバの中に書くと、CLI からも図の生成からも再利用できず、
何より **テストできない**。だから `chain/` 側に置く。

`web/` は `chain/` を呼ぶが、`chain/` は `web/` を知らない。この向きは崩さない。

進捗の返し方
------------
シナリオは **ジェネレータ** にしてある。1 ステップ進むごとに
その内容を yield し、最終結果は return する（`StopIteration.value` で取れる）。

こうしておくと、呼ぶ側が「1 ステップごとにロックを取り直す」制御を持てる。
Web サーバは攻撃の実行中も UI に状態を返し続けたいので、これが必要になる。
シナリオ側にロックを持ち込むと、engine が Web の都合を知ることになってしまう。
"""

from __future__ import annotations

from typing import Iterator

from node import Network, Node
from tx import InvalidTx, Wallet, transfer


def double_spend(net: Network, attacker: Wallet, merchant: Wallet,
                 amount: int = 40, confirmations: int = 3,
                 lead: int = 2, attacker_node: Node | None = None
                 ) -> Iterator[str]:
    """確認済みの支払いを、隠して掘った重い枝で消す。

    現実の 51% 攻撃とまったく同じ手順を踏む。

      1. 攻撃者が商店へ支払い、ネットワークに取り込ませる
      2. 商店は confirmations ブロック待ってから商品を渡す
      3. 攻撃者は「支払いブロックの 1 つ手前」から、支払いを含まない枝を
         秘密裏に掘り続けていた
      4. 正直枝より重くなった時点で一斉公開する
         → 最大仕事量ルールにより tip が載せ替わり、支払いが無かったことになる

    重要なのは、この間 **不正なブロックを 1 つも作っていない** こと。
    署名も PoW もマークル根も全部有効。破っているのは暗号ではなく、
    「一度確認されたら確定」という思い込みのほう。

    Yields: 各ステップの説明
    Returns: 結果の辞書（呼び出し側は StopIteration.value で受け取る）
    """
    node = attacker_node or net.nodes[-1]
    observer = net.nodes[0]

    # ---- 準備: 攻撃者に元手を持たせる
    if attacker.balance(observer.chain.utxos) < amount:
        donor = max(net.nodes, key=lambda n: n.wallet.balance(observer.chain.utxos))
        if donor.wallet.balance(observer.chain.utxos) < amount:
            raise InvalidTx("元手が足りません。先に数ブロック採掘してください")
        seed = transfer(donor.wallet, observer.chain.utxos, attacker.address, amount)
        net.submit_tx(seed, origin=donor.id)
        yield "攻撃者に元手を渡した"
        for _ in range(2):
            net.mine_next()
            yield "元手を確定させるために採掘"
        net.settle()

    # ---- 1. 支払い
    payment = transfer(attacker, observer.chain.utxos, merchant.address, amount)
    net.submit_tx(payment, origin=0)
    net._emit("attack", f"{attacker.name} → {merchant.name} {amount} を送金（攻撃開始）")
    yield "支払い tx を投入した"

    # ---- 2. 取り込みと確認待ち
    pay_block = None
    for _ in range(confirmations + 3):
        net.mine_next()
        net.settle()
        if pay_block is None:
            pay_block = _block_containing(observer, payment.txid())
        yield "確認を積んでいる"
        if pay_block is not None and _depth(observer, pay_block) > confirmations:
            break

    if pay_block is None:
        raise InvalidTx("支払いがチェーンに取り込まれませんでした")

    fork_point = observer.chain.blocks[pay_block].header.prev_hash
    honest_tip = observer.chain.tip
    honest_work = observer.chain.work[honest_tip]
    honest_height = observer.chain.height()
    merchant_before = merchant.balance(observer.chain.utxos)
    net._emit("attack",
              f"{merchant.name} の残高 {merchant_before} を "
              f"{_depth(observer, pay_block)} 確認で確認済み → 商品を発送")
    yield "商店が商品を発送した"

    # ---- 3. 隠し枝を掘る
    # 分岐点は支払いブロックの 1 つ手前。この枝には支払い tx を入れず、
    # 同じ UTXO を自分自身へ送る tx を入れる。
    self_pay = transfer(attacker, observer.chain.utxo_for(fork_point),
                        attacker.address, amount)
    hidden, tip = [], fork_point
    need = honest_height - observer.chain.height(fork_point) + lead
    for i in range(need):
        blk = node.chain.mine_block(node.wallet, [self_pay] if i == 0 else [], on=tip)
        node.chain.add(blk)
        hidden.append(blk)
        tip = blk.hash()
        yield f"隠し枝を {len(hidden)}/{need} ブロック掘った"

    # ---- 4. 一斉公開
    for blk in hidden:
        net._send(node.id, "block", blk)
    net._emit("attack", f"隠していた {len(hidden)} ブロックを一斉公開")
    net.settle()
    yield "隠し枝を公開した"

    merchant_after = merchant.balance(observer.chain.utxos)
    survived = observer.chain.contains_tx(payment.txid())
    net._emit("attack",
              f"リオーグ完了 → {merchant.name} 残高 "
              f"{merchant_before} → {merchant_after}")

    return {
        "kind": "double_spend",
        "succeeded": not survived,
        "amount": amount,
        "confirmations": confirmations,
        "hidden_blocks": len(hidden),
        "honest_work": honest_work,
        "attack_work": observer.chain.work[observer.chain.tip],
        "payment_txid": payment.txid().hex(),
        "payment_survived": survived,
        "merchant_before": merchant_before,
        "merchant_after": merchant_after,
        "honest_tip": honest_tip.hex(),
        "fork_point": fork_point.hex(),
    }


def _block_containing(node: Node, txid: bytes) -> bytes | None:
    for blk in node.chain.branch():
        for t in blk.txs:
            if t.txid() == txid:
                return blk.hash()
    return None


def _depth(node: Node, block_hash: bytes) -> int:
    """そのブロックが何確認ぶん埋まっているか（自身を 1 と数える）。"""
    if block_hash not in node.chain.blocks:
        return 0
    return node.chain.height() - node.chain.height(block_hash) + 1


def run(gen: Iterator[str], on_step=None) -> dict:
    """ジェネレータを最後まで回して結果を取り出す小道具。

    進捗を気にしない呼び出し側（CLI、図の生成、テスト）はこれを使う。
    """
    while True:
        try:
            step = next(gen)
        except StopIteration as stop:
            return stop.value
        if on_step:
            on_step(step)


# ---------------------------------------------------------------- 自己確認

def self_check() -> None:
    net = Network(node_count=3, difficulty=8, latency=1.0,
                  block_interval=30.0, seed=2026)
    net.run(4)
    net.settle()

    alice = net.wallet("Alice")
    merchant = net.wallet("Merchant")
    result = run(double_spend(net, alice, merchant, amount=30,
                              confirmations=2, lead=2))

    assert result["succeeded"], "攻撃が成功しなかった"
    assert not result["payment_survived"]
    assert result["merchant_before"] == 30
    assert result["merchant_after"] == 0
    assert result["attack_work"] > result["honest_work"]
    # 正直枝のブロックは消えていない。選ばれなくなっただけ。
    assert bytes.fromhex(result["honest_tip"]) in net.nodes[0].chain.blocks

    print("  [ok] scenario.py 自己確認 通過")


def demo() -> None:
    net = Network(node_count=4, difficulty=12, latency=4.0,
                  block_interval=30.0, seed=7)
    net.run(8)
    net.settle()
    alice, merchant = net.wallet("Alice"), net.wallet("Merchant")

    print("\n-- 二重支払い攻撃を頭から流す ----------------------------------")
    result = run(double_spend(net, alice, merchant, amount=40,
                              confirmations=3, lead=2),
                 on_step=lambda s: print(f"    · {s}"))

    print(f"\n    支払い tx        {result['payment_txid'][:16]}…")
    print(f"    隠し枝の長さ     {result['hidden_blocks']} ブロック")
    print(f"    正直枝の仕事量   {result['honest_work']:,}")
    print(f"    攻撃枝の仕事量   {result['attack_work']:,}")
    print(f"    支払いは有効か   {result['payment_survived']}")
    print(f"    商店の残高       {result['merchant_before']} → {result['merchant_after']}")
    print(f"    孤児ブロック     {net.stats()['orphans']} 個")
    print("""
    → 攻撃に使ったのは「正直者より速く掘る」ことだけ。
      不正なブロックは 1 つも作っていない。

    → 正直枝のブロックは今もノードのデータベースに残っている。
      消えたのではなく、選ばれなくなっただけ。
""")


if __name__ == "__main__":
    from util import enable_utf8_stdout

    enable_utf8_stdout()
    self_check()
    demo()
