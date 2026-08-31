"""
決済レイヤ — 確率的な合意の上に、どうやって商売を載せるか

なぜ必要か
----------
ここまでで作ったチェーンは「送金が有効かどうか」を判定できる。
しかし店をやるには、それだけでは決定的に足りない。

    tx が有効であることと、商品を渡してよいことは、まったく別。

Phase 7 で見たとおり、ブロックチェーンに「確定」は存在しない。
あるのは「覆すのに必要な費用」だけ。だから決済システムは必ずどこかで

    **どこまで待ったら、商品を渡すことにするか**

を決めなければならない。これは暗号の問題ではなく、経営判断。
BitPay も取引所も、毎日この判断をしている。

このモジュールは、その判断を明示的なコードにしたもの。

現実の決済事業者と同じ設計にしてある
------------------------------------
- **請求書ごとに新しいアドレスを発行する**（誰の支払いか識別するため）
- **店は自分のノードを持つ**（他人に「入金しました」と言われて信じない）
- **0 確認では絶対に渡さない**（Phase 7 の表で成功率 100%）
- **金額で待つ長さを変える**（期待損失を一定以下に抑える）
- **一度確定した注文が巻き戻る状態を持つ**（reversed。これが最大の違い）

最後の 1 つが、クレジットカードにもない、ブロックチェーン決済に固有の状態。
チャージバックと違って、誰の意思でもなく、ただ確率で起きる。

到達点
------
- 請求書が created → detected → confirming → settled と進むのを追える
- 金額を上げると必要確認数が増えることを、期待損失の式から説明できる
- 51% 攻撃で settled の注文が reversed に落ちるのを再現できる
"""

from __future__ import annotations

import itertools
from dataclasses import dataclass, field

from chain import attacker_success_probability
from node import Node
from tx import Tx, Wallet, addr_str, transfer


# ---------------------------------------------------------------- 確認数ポリシー

def required_confirmations(amount: int, attacker_share: float = 0.10,
                           tolerated_loss: float = 0.5,
                           cap: int = 24) -> int:
    """この金額なら何確認待つべきか。

    考え方は保険と同じ。**期待損失** を一定額以下に抑える。

        期待損失 = P(攻撃者が z 確認を覆す確率) × 金額

    これが tolerated_loss を下回る最小の z を返す。
    金額が大きいほど z が大きくなる。取引所が高額入金に多くの確認を
    要求するのは、この式をやっているのと同じこと。

    z = 0 は絶対に返らない。P(q, 0) = 1 なので、
    どんなに小さい金額でも期待損失 = 全額になるため。
    「0 確認で渡してよい額」は原理的に存在しない。

    Args:
        amount:          請求額
        attacker_share:  想定する攻撃者のハッシュ力（0.10 = 10%）
        tolerated_loss:  1 件あたり許容する期待損失（額）
        cap:             これ以上は待たない上限
    """
    for z in range(0, cap + 1):
        if attacker_success_probability(attacker_share, z) * amount <= tolerated_loss:
            return max(z, 1)                  # 0 確認は選ばせない
    return cap


def confirmation_table(amounts: list[int], attacker_share: float = 0.10,
                       tolerated_loss: float = 0.5) -> list[tuple[int, int, float]]:
    """金額ごとの必要確認数と、そのときの期待損失。UI と demo が使う。"""
    rows = []
    for amount in amounts:
        z = required_confirmations(amount, attacker_share, tolerated_loss)
        loss = attacker_success_probability(attacker_share, z) * amount
        rows.append((amount, z, loss))
    return rows


# ---------------------------------------------------------------- 請求書

# 状態遷移:
#
#     created ──支払いを mempool で発見──▶ detected
#        │                                    │
#        │ 期限切れ                            │ ブロックに入った
#        ▼                                    ▼
#     expired                            confirming ──必要確認数に到達──▶ settled
#                                             │                             │
#                                             │ 金額が足りない               │ リオーグ
#                                             ▼                             ▼
#                                        underpaid                      reversed
#
# reversed が、この決済方式に固有の状態。
# 「確定したと思ったものが確定していなかった」を表現する場所がないと、
# 商品を渡したあとに何が起きたのかをシステムが記録できない。

CREATED = "created"
DETECTED = "detected"          # mempool で見えた。0 確認。渡してはいけない
CONFIRMING = "confirming"      # ブロックに入った。まだ足りない
SETTLED = "settled"            # 必要確認数に到達。渡してよい
UNDERPAID = "underpaid"        # 金額が足りない
EXPIRED = "expired"            # 期限切れ
REVERSED = "reversed"          # 確定後にリオーグで消えた

TERMINAL = {EXPIRED}
_ids = itertools.count(1001)


@dataclass
class Invoice:
    """1 件の請求書。

    アドレスは請求書ごとに新しく作る。使い回すと、
    「誰がどの請求に払ったのか」がチェーンから判別できなくなる。
    現実の決済ゲートウェイも必ずこうしている。
    """
    amount: int
    memo: str = ""
    attacker_share: float = 0.10
    tolerated_loss: float = 0.5
    expires_after: float = 600.0              # 模擬時刻での秒数

    id: int = field(default_factory=lambda: next(_ids))
    wallet: Wallet = field(default_factory=lambda: Wallet("invoice"))
    created_at: float = 0.0

    status: str = CREATED
    required: int = 0
    confirmations: int = 0
    received: int = 0
    paid_txid: bytes | None = None
    paid_block: bytes | None = None
    history: list[tuple[float, str, str]] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.required:
            self.required = required_confirmations(
                self.amount, self.attacker_share, self.tolerated_loss)

    @property
    def address(self) -> bytes:
        return self.wallet.address

    def note(self, now: float, text: str) -> None:
        self.history.append((round(now, 2), self.status, text))

    def set_status(self, now: float, status: str, text: str) -> None:
        if self.status == status:
            return
        before = self.status
        self.status = status
        self.history.append((round(now, 2), status, text))
        if status == SETTLED:
            self.history.append((round(now, 2), status, "→ 商品を引き渡してよい"))
        if status == REVERSED:
            self.history.append(
                (round(now, 2), status,
                 f"→ {before} だった注文が巻き戻された。商品は戻ってこない"))

    def safe_to_release(self) -> bool:
        """商品を渡してよいか。settled のときだけ True。"""
        return self.status == SETTLED

    def view(self) -> dict:
        return {
            "id": self.id,
            "amount": self.amount,
            "memo": self.memo,
            "address": addr_str(self.address),
            "status": self.status,
            "required": self.required,
            "confirmations": self.confirmations,
            "received": self.received,
            "txid": self.paid_txid.hex()[:16] if self.paid_txid else None,
            "risk": attacker_success_probability(self.attacker_share,
                                                 self.confirmations),
            "expected_loss": attacker_success_probability(
                self.attacker_share, self.confirmations) * self.amount,
            "safe": self.safe_to_release(),
            "history": [{"t": t, "status": s, "text": x}
                        for t, s, x in self.history[-12:]],
        }


# ---------------------------------------------------------------- 決済処理

class PaymentProcessor:
    """店舗側の決済システム。自分のノードだけを根拠に判断する。

    重要なのは、外から「入金しました」と言われても一切信じないこと。
    信じるのは自分のノードが持っているチェーンの中身だけ。
    これができるのがブロックチェーン決済の利点で、
    そのために店がフルノードを持つ意味がある。
    """

    def __init__(self, node: Node, name: str = "Merchant") -> None:
        self.node = node
        self.name = name
        self.invoices: dict[int, Invoice] = {}
        self.released: set[int] = set()        # 商品を渡した注文
        self.log: list[dict] = []

    # ------------------------------------------------------------ 発行

    def create_invoice(self, amount: int, memo: str = "", now: float = 0.0,
                       **policy) -> Invoice:
        inv = Invoice(amount=amount, memo=memo, created_at=now, **policy)
        inv.note(now, f"請求書 #{inv.id} 発行 — {amount} / 必要 {inv.required} 確認")
        self.invoices[inv.id] = inv
        self._log(now, "invoice",
                  f"#{inv.id} {amount} を発行（{inv.required} 確認で確定）")
        return inv

    # ------------------------------------------------------------ 監視

    def poll(self, now: float) -> list[Invoice]:
        """チェーンと mempool を見て、全請求書の状態を更新する。

        毎回チェーンを頭から見直しているのは、リオーグを検出するため。
        「前に見たときは入っていたのに、今は入っていない」を
        取りこぼさない書き方にしてある。
        """
        changed = []
        chain = self.node.chain
        tip_height = chain.height() if chain.tip else -1

        # 正典チェーンのどこに何が入っているか
        canonical: dict[bytes, tuple[int, Tx]] = {}
        for blk in chain.branch():
            h = chain.height(blk.hash())
            for t in blk.txs:
                canonical[t.txid()] = (h, t)

        for inv in self.invoices.values():
            if inv.status in TERMINAL:
                continue
            before = inv.status

            paid_in_chain = self._find_payment(inv, canonical)
            if paid_in_chain:
                height, t, received = paid_in_chain
                inv.received = received
                inv.paid_txid = t.txid()
                inv.paid_block = None
                inv.confirmations = tip_height - height + 1
                if received < inv.amount:
                    inv.set_status(now, UNDERPAID,
                                   f"{received} しか届いていない（要求 {inv.amount}）")
                elif inv.confirmations >= inv.required:
                    inv.set_status(now, SETTLED,
                                   f"{inv.confirmations} 確認に到達")
                else:
                    inv.set_status(
                        now, CONFIRMING,
                        f"ブロックに取り込まれた（{inv.confirmations}/{inv.required} 確認）")
            else:
                mempool_pay = self._find_in_mempool(inv)
                if mempool_pay:
                    t, received = mempool_pay
                    inv.received = received
                    inv.paid_txid = t.txid()
                    inv.confirmations = 0
                    if before in (SETTLED, CONFIRMING):
                        inv.set_status(now, REVERSED,
                                       "リオーグで正典チェーンから外れ、mempool に戻った")
                    else:
                        inv.set_status(now, DETECTED,
                                       "mempool で支払いを検出（0 確認）")
                elif before in (SETTLED, CONFIRMING):
                    inv.confirmations = 0
                    inv.received = 0
                    inv.set_status(now, REVERSED,
                                   "リオーグで支払いがチェーンから消えた")
                elif (before in (CREATED, DETECTED)
                      and now - inv.created_at > inv.expires_after):
                    inv.set_status(now, EXPIRED, "期限切れ")

            if inv.status != before:
                changed.append(inv)
                self._log(now, inv.status,
                          f"#{inv.id} {before} → {inv.status}"
                          + (f"（{inv.confirmations}/{inv.required} 確認）"
                             if inv.status == CONFIRMING else ""))
                if inv.status == REVERSED and inv.id in self.released:
                    self._log(now, "loss",
                              f"#{inv.id} は商品を渡したあとで巻き戻された。"
                              f"損失 {inv.amount}")

        return changed

    def _find_payment(self, inv: Invoice,
                      canonical: dict) -> tuple[int, Tx, int] | None:
        for txid, (height, t) in canonical.items():
            received = sum(o.amount for o in t.outputs if o.address == inv.address)
            if received > 0:
                return height, t, received
        return None

    def _find_in_mempool(self, inv: Invoice) -> tuple[Tx, int] | None:
        for t in self.node.mempool.values():
            received = sum(o.amount for o in t.outputs if o.address == inv.address)
            if received > 0:
                return t, received
        return None

    # ------------------------------------------------------------ 引き渡し

    def release(self, invoice_id: int, now: float, force: bool = False
                ) -> tuple[bool, str]:
        """商品を引き渡す。

        settled 以外で渡そうとしたら止める。`force=True` で押し切れるのは、
        「0 確認で渡すとどうなるか」を実験するため。
        現実の決済システムにも、この押し切りボタンは（残念ながら）ある。
        """
        inv = self.invoices[invoice_id]
        if inv.safe_to_release() or force:
            self.released.add(invoice_id)
            level = "release" if inv.safe_to_release() else "risky"
            inv.note(now, "商品を引き渡した"
                     + ("" if inv.safe_to_release()
                        else f"（{inv.status} のまま強行）"))
            self._log(now, level,
                      f"#{invoice_id} 商品を引き渡した"
                      + ("" if inv.safe_to_release()
                         else f" ← {inv.status} のまま強行。リオーグで消える可能性"))
            return True, "引き渡しました"
        return False, (f"#{invoice_id} はまだ {inv.status} です"
                       f"（{inv.confirmations}/{inv.required} 確認）")

    def losses(self) -> list[Invoice]:
        """商品を渡したのに巻き戻された注文。"""
        return [inv for inv in self.invoices.values()
                if inv.status == REVERSED and inv.id in self.released]

    # ------------------------------------------------------------ 補助

    def _log(self, now: float, kind: str, text: str) -> None:
        self.log.append({"t": round(now, 2), "kind": kind, "text": text})
        del self.log[:-200]

    def summary(self) -> dict:
        by_status: dict[str, int] = {}
        for inv in self.invoices.values():
            by_status[inv.status] = by_status.get(inv.status, 0) + 1
        lost = self.losses()
        return {
            "invoices": len(self.invoices),
            "by_status": by_status,
            "released": len(self.released),
            "reversed_after_release": len(lost),
            "lost_amount": sum(inv.amount for inv in lost),
        }


def pay_invoice(payer: Wallet, node: Node, inv: Invoice, network,
                fee: int = 1, amount: int | None = None) -> Tx:
    """客側。請求書のアドレスへ送金してネットワークに流す。"""
    t = transfer(payer, node.chain.utxos, inv.address,
                 amount if amount is not None else inv.amount, fee=fee)
    network.submit_tx(t, origin=node.id)
    return t


# ---------------------------------------------------------------- 自己確認

def self_check() -> None:
    from node import Network

    # --- 確認数ポリシー
    assert required_confirmations(1) >= 1, "0 確認を返してはいけない"
    small = required_confirmations(10)
    large = required_confirmations(10_000)
    assert large > small, "高額なのに待つ長さが同じ"
    # 単調性: 金額が増えて必要確認数が減ることはない
    zs = [required_confirmations(a) for a in (1, 10, 100, 1000, 10_000)]
    assert zs == sorted(zs), zs

    # --- 請求書のライフサイクル
    net = Network(node_count=3, difficulty=8, latency=0.0,
                  block_interval=30.0, seed=555)
    net.run(4)
    net.settle()

    merchant_node = net.nodes[0]
    pos = PaymentProcessor(merchant_node, "TestShop")
    alice = net.wallet("Alice")

    # Alice に元手
    donor = max(net.nodes, key=lambda n: n.wallet.balance(merchant_node.chain.utxos))
    net.submit_tx(transfer(donor.wallet, merchant_node.chain.utxos,
                           alice.address, 100), origin=donor.id)
    net.run(2)
    net.settle()

    inv = pos.create_invoice(20, "コーヒー", now=net.now, tolerated_loss=0.5)
    assert inv.status == CREATED
    assert inv.required >= 1

    # 支払い前は渡せない
    ok, _ = pos.release(inv.id, net.now)
    assert not ok, "未払いなのに引き渡せてしまった"

    pay_invoice(alice, merchant_node, inv, net)
    pos.poll(net.now)
    assert inv.status == DETECTED, inv.status
    assert not inv.safe_to_release(), "0 確認で安全判定が出ている"

    net.mine_next()
    net.settle()
    pos.poll(net.now)
    assert inv.status in (CONFIRMING, SETTLED), inv.status

    for _ in range(inv.required + 1):
        net.mine_next()
        net.settle()
        pos.poll(net.now)
    assert inv.status == SETTLED, inv.status
    assert inv.safe_to_release()
    ok, _ = pos.release(inv.id, net.now)
    assert ok

    # --- 金額が足りない場合
    inv2 = pos.create_invoice(50, "ケーキ", now=net.now)
    pay_invoice(alice, merchant_node, inv2, net, amount=10)
    net.mine_next()
    net.settle()
    pos.poll(net.now)
    assert inv2.status == UNDERPAID, inv2.status

    print("  [ok] payment.py 自己確認 通過")


def demo() -> None:
    import scenario
    from node import Network

    print("\n-- 観察 1: 金額で待つ長さが変わる ------------------------------")
    print("  期待損失 = P(攻撃者が z 確認を覆す確率) × 金額 を 0.5 以下に抑える。")
    print(f"\n    {'金額':>10} {'必要確認数':>12} {'そのときの期待損失':>20}")
    print("    " + "-" * 46)
    for amount, z, loss in confirmation_table(
            [1, 10, 100, 1_000, 10_000, 100_000, 1_000_000]):
        print(f"    {amount:>10,} {z:>12} {loss:>20.4f}")
    print("""
    → 取引所が高額入金に多くの確認を要求するのは、この式をやっているのと同じ。
      「6 確認」は金額を無視した慣習で、本当は額ごとに決めるべきもの。

    → z = 0 が返ることは絶対にない。P(q, 0) = 1 なので、
      どんなに小さい額でも期待損失は全額になる。
      「0 確認で渡してよい額」は原理的に存在しない。
""")

    print("-- 観察 2: 注文が確定するまで ----------------------------------")
    net = Network(node_count=4, difficulty=12, latency=3.0,
                  block_interval=30.0, seed=8888)
    net.run(8)
    net.settle()

    shop_node = net.nodes[0]
    pos = PaymentProcessor(shop_node, "コーヒースタンド")
    alice = net.wallet("Alice")
    donor = max(net.nodes, key=lambda n: n.wallet.balance(shop_node.chain.utxos))
    net.submit_tx(transfer(donor.wallet, shop_node.chain.utxos,
                           alice.address, 100), origin=donor.id)
    net.run(2)
    net.settle()

    inv = pos.create_invoice(40, "ドリップコーヒー", now=net.now)
    print(f"    請求書 #{inv.id}  {inv.amount}  → 必要 {inv.required} 確認")
    print(f"    支払先アドレス {addr_str(inv.address)}（この請求書専用）")

    pay_invoice(alice, shop_node, inv, net)
    pos.poll(net.now)
    print(f"\n    [{net.now:>7.1f}s] {inv.status:<11} 確認 {inv.confirmations}"
          f"  期待損失 {inv.view()['expected_loss']:.2f}"
          f"  渡してよいか: {inv.safe_to_release()}")

    for _ in range(inv.required + 2):
        net.mine_next()
        net.settle()
        pos.poll(net.now)
        print(f"    [{net.now:>7.1f}s] {inv.status:<11} 確認 {inv.confirmations}"
              f"  期待損失 {inv.view()['expected_loss']:.2f}"
              f"  渡してよいか: {inv.safe_to_release()}")
        if inv.status == SETTLED:
            break

    pos.release(inv.id, net.now)
    print("\n    → 期待損失が下がっていくのが見える。これが『待つ』の中身。")

    print("\n-- 観察 3: 待たずに渡すとどうなるか -------------------------")
    net2 = Network(node_count=4, difficulty=12, latency=3.0,
                   block_interval=30.0, seed=4242)
    net2.run(8)
    net2.settle()
    shop2 = net2.nodes[0]
    pos2 = PaymentProcessor(shop2, "せっかちな店")
    alice2 = net2.wallet("Alice")
    donor2 = max(net2.nodes, key=lambda n: n.wallet.balance(shop2.chain.utxos))
    net2.submit_tx(transfer(donor2.wallet, shop2.chain.utxos,
                            alice2.address, 100), origin=donor2.id)
    net2.run(2)
    net2.settle()

    inv2 = pos2.create_invoice(40, "高額商品", now=net2.now)
    print(f"    請求書 #{inv2.id} {inv2.amount} — ポリシーは {inv2.required} 確認")
    print("    ところが店は「1 確認あれば十分だろう」と判断して渡してしまう。")

    # 攻撃者は、この請求書のアドレス宛てに払ってから枝を掘り直す。
    # 請求書は専用ウォレットを持っているので、そのまま受取人として渡せる。
    def watch(step: str) -> None:
        pos2.poll(net2.now)
        if (inv2.confirmations >= 1 and inv2.id not in pos2.released
                and inv2.status in (CONFIRMING, SETTLED)):
            pos2.release(inv2.id, net2.now, force=True)
            print(f"    [{net2.now:>7.1f}s] {inv2.confirmations} 確認で商品を渡した"
                  f"（期待損失 {inv2.view()['expected_loss']:.2f} を無視）")

    scenario.run(scenario.double_spend(
        net2, alice2, inv2.wallet, amount=40, confirmations=1, lead=2),
        on_step=watch)
    pos2.poll(net2.now)

    print(f"    [{net2.now:>7.1f}s] 攻撃者が隠し枝を公開 → 注文は {inv2.status}")
    s2 = pos2.summary()
    print(f"\n    引き渡した注文 {s2['released']} 件 / "
          f"うち巻き戻された {s2['reversed_after_release']} 件 / "
          f"損失 {s2['lost_amount']}")
    for t, status, textline in inv2.history[-4:]:
        print(f"      [{t:>7.1f}s] {status:<11} {textline}")
    print("""
    → 待つ長さを 4 確認から 1 確認に縮めた、それだけで商品が消えた。
      チェーンも署名も一切壊れていない。壊れたのは店の判断のほう。

    → 決済システムの仕事は、暗号を正しく使うことではない。
      「どこで信じることにするか」を決めて、その判断を記録に残すこと。

    → クレジットカードのチャージバックと違い、リオーグは誰の意思でもない。
      交渉相手がいないので、事後に取り返す手段が存在しない。
      だから事前に『何確認待つか』でしか制御できない。
""")


if __name__ == "__main__":
    from util import enable_utf8_stdout

    enable_utf8_stdout()
    self_check()
    demo()
