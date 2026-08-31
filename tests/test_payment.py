"""
決済レイヤのテスト

    python -m unittest tests.test_payment -v

ここで守りたいのは 2 つ。

  1. **0 確認で安全判定が出ないこと**。P(q, 0) = 1 なので、
     どんなに小さい額でも 0 確認は全損の期待値を持つ。
     ここが緩むと、教材としても製品としても嘘になる。

  2. **巻き戻りが記録として残ること**。商品を渡したあとで支払いが消えた、
     という事実を表現できないシステムは、事故があったことに気づけない。
"""

from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "chain"))

import payment                                                    # noqa: E402
import scenario                                                   # noqa: E402
from node import Network                                          # noqa: E402
from tx import transfer                                           # noqa: E402


def funded_network(seed: int, blocks: int = 8, give: int = 100):
    """数ブロック掘って Alice に元手を持たせたネットワークを返す。"""
    net = Network(node_count=4, difficulty=8, latency=1.0,
                  block_interval=30.0, seed=seed)
    net.run(blocks)
    net.settle()
    shop = net.nodes[0]
    alice = net.wallet("Alice")
    donor = max(net.nodes, key=lambda n: n.wallet.balance(shop.chain.utxos))
    net.submit_tx(transfer(donor.wallet, shop.chain.utxos, alice.address, give),
                  origin=donor.id)
    net.run(2)
    net.settle()
    return net, shop, alice


class TestConfirmationPolicy(unittest.TestCase):
    def test_never_returns_zero(self):
        """0 確認を返してはいけない。P(q, 0) = 1 なので期待損失 = 全額。"""
        for amount in (1, 2, 5, 10, 1000):
            self.assertGreaterEqual(payment.required_confirmations(amount), 1)

    def test_larger_amount_needs_more_confirmations(self):
        zs = [payment.required_confirmations(a)
              for a in (1, 10, 100, 1_000, 10_000, 100_000)]
        self.assertEqual(zs, sorted(zs))
        self.assertGreater(zs[-1], zs[0])

    def test_stronger_attacker_needs_more_confirmations(self):
        weak = payment.required_confirmations(1000, attacker_share=0.05)
        strong = payment.required_confirmations(1000, attacker_share=0.35)
        self.assertGreater(strong, weak)

    def test_tighter_tolerance_needs_more_confirmations(self):
        loose = payment.required_confirmations(1000, tolerated_loss=5.0)
        tight = payment.required_confirmations(1000, tolerated_loss=0.01)
        self.assertGreater(tight, loose)

    def test_respects_cap(self):
        self.assertLessEqual(
            payment.required_confirmations(10**12, attacker_share=0.45, cap=12), 12)

    def test_expected_loss_is_under_tolerance(self):
        from chain import attacker_success_probability
        for amount in (10, 100, 10_000):
            z = payment.required_confirmations(amount, 0.10, 0.5)
            loss = attacker_success_probability(0.10, z) * amount
            self.assertLessEqual(loss, 0.5 + 1e-9, f"amount={amount} z={z}")


class TestInvoiceLifecycle(unittest.TestCase):
    def setUp(self):
        self.net, self.shop, self.alice = funded_network(seed=101)
        self.pos = payment.PaymentProcessor(self.shop, "TestShop")

    def test_starts_created(self):
        inv = self.pos.create_invoice(20, now=self.net.now)
        self.assertEqual(inv.status, payment.CREATED)
        self.assertGreaterEqual(inv.required, 1)
        self.assertFalse(inv.safe_to_release())

    def test_each_invoice_gets_a_fresh_address(self):
        a = self.pos.create_invoice(10, now=self.net.now)
        b = self.pos.create_invoice(10, now=self.net.now)
        self.assertNotEqual(a.address, b.address)

    def test_mempool_payment_is_detected_but_not_safe(self):
        inv = self.pos.create_invoice(20, now=self.net.now)
        payment.pay_invoice(self.alice, self.shop, inv, self.net)
        self.pos.poll(self.net.now)
        self.assertEqual(inv.status, payment.DETECTED)
        self.assertEqual(inv.confirmations, 0)
        self.assertFalse(inv.safe_to_release(),
                         "0 確認で安全判定が出ている")

    def test_cannot_release_before_settled(self):
        inv = self.pos.create_invoice(20, now=self.net.now)
        payment.pay_invoice(self.alice, self.shop, inv, self.net)
        self.pos.poll(self.net.now)
        ok, _ = self.pos.release(inv.id, self.net.now)
        self.assertFalse(ok)
        self.assertNotIn(inv.id, self.pos.released)

    def test_reaches_settled_and_can_release(self):
        inv = self.pos.create_invoice(20, now=self.net.now)
        payment.pay_invoice(self.alice, self.shop, inv, self.net)
        for _ in range(inv.required + 3):
            self.net.mine_next()
            self.net.settle()
            self.pos.poll(self.net.now)
            if inv.status == payment.SETTLED:
                break
        self.assertEqual(inv.status, payment.SETTLED)
        self.assertGreaterEqual(inv.confirmations, inv.required)
        ok, _ = self.pos.release(inv.id, self.net.now)
        self.assertTrue(ok)

    def test_expected_loss_decreases_with_confirmations(self):
        inv = self.pos.create_invoice(40, now=self.net.now)
        payment.pay_invoice(self.alice, self.shop, inv, self.net)
        self.pos.poll(self.net.now)
        losses = [inv.view()["expected_loss"]]
        for _ in range(inv.required):
            self.net.mine_next()
            self.net.settle()
            self.pos.poll(self.net.now)
            losses.append(inv.view()["expected_loss"])
        self.assertEqual(losses, sorted(losses, reverse=True), losses)
        self.assertEqual(losses[0], inv.amount, "0 確認の期待損失は全額のはず")

    def test_underpayment_is_flagged(self):
        inv = self.pos.create_invoice(50, now=self.net.now)
        payment.pay_invoice(self.alice, self.shop, inv, self.net, amount=10)
        self.net.mine_next()
        self.net.settle()
        self.pos.poll(self.net.now)
        self.assertEqual(inv.status, payment.UNDERPAID)
        self.assertFalse(inv.safe_to_release())

    def test_expires_without_payment(self):
        inv = self.pos.create_invoice(20, now=self.net.now, expires_after=1.0)
        self.net.now += 5.0
        self.pos.poll(self.net.now)
        self.assertEqual(inv.status, payment.EXPIRED)


class TestReversal(unittest.TestCase):
    """商品を渡したあとで支払いが消える、というこの方式に固有の事故。"""

    def test_release_at_one_confirmation_can_be_reversed(self):
        net, shop, alice = funded_network(seed=202)
        pos = payment.PaymentProcessor(shop, "せっかちな店")
        inv = pos.create_invoice(40, "高額商品", now=net.now)
        self.assertGreater(inv.required, 1, "そもそも 1 確認では足りない設定であること")

        def watch(step):
            pos.poll(net.now)
            if (inv.confirmations >= 1 and inv.id not in pos.released
                    and inv.status in (payment.CONFIRMING, payment.SETTLED)):
                pos.release(inv.id, net.now, force=True)

        scenario.run(scenario.double_spend(
            net, alice, inv.wallet, amount=40, confirmations=1, lead=2),
            on_step=watch)
        pos.poll(net.now)

        self.assertIn(inv.id, pos.released, "店が商品を渡していない")
        self.assertEqual(inv.status, payment.REVERSED)
        self.assertEqual(len(pos.losses()), 1)
        self.assertEqual(pos.summary()["lost_amount"], 40)

    def test_history_records_the_reversal(self):
        net, shop, alice = funded_network(seed=303)
        pos = payment.PaymentProcessor(shop)
        inv = pos.create_invoice(40, now=net.now)
        scenario.run(scenario.double_spend(
            net, alice, inv.wallet, amount=40, confirmations=1, lead=2),
            on_step=lambda s: pos.poll(net.now))
        pos.poll(net.now)
        self.assertEqual(inv.status, payment.REVERSED)
        texts = " ".join(h[2] for h in inv.history)
        self.assertIn("巻き戻", texts, "巻き戻りが履歴に残っていない")

    def test_waiting_long_enough_survives_the_same_attack(self):
        """同じ攻撃でも、ポリシーどおり待てば商品を渡す前に気づける。

        攻撃者が 1 確認しか稼がせないなら、4 確認を待つ店は
        そもそも settled にならないので引き渡さない。
        """
        net, shop, alice = funded_network(seed=404)
        pos = payment.PaymentProcessor(shop, "待つ店")
        inv = pos.create_invoice(40, now=net.now)

        def strict(step):
            pos.poll(net.now)
            if inv.safe_to_release() and inv.id not in pos.released:
                pos.release(inv.id, net.now)          # force しない

        scenario.run(scenario.double_spend(
            net, alice, inv.wallet, amount=40, confirmations=1, lead=2),
            on_step=strict)
        pos.poll(net.now)

        self.assertEqual(pos.summary()["reversed_after_release"], 0,
                         "ポリシーを守ったのに損失が出ている")


class TestProcessorTrustsOnlyItsOwnNode(unittest.TestCase):
    def test_uses_its_own_chain_view(self):
        """店の判定根拠が、自分のノードのチェーンだけであること。"""
        net, shop, alice = funded_network(seed=505)
        pos = payment.PaymentProcessor(shop)
        self.assertIs(pos.node, shop)

        inv = pos.create_invoice(20, now=net.now)
        payment.pay_invoice(alice, shop, inv, net)

        # まだ誰も掘っていないので、どのノードから見ても 0 確認
        pos.poll(net.now)
        self.assertEqual(inv.confirmations, 0)

        net.mine_next()
        net.settle()
        pos.poll(net.now)
        self.assertEqual(inv.confirmations,
                         shop.chain.height() - shop.chain.height(
                             next(b.hash() for b in shop.chain.branch()
                                  for t in b.txs if t.txid() == inv.paid_txid)) + 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
