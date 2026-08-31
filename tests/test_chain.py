"""
テストスイート（標準ライブラリの unittest のみ）

    python -m unittest discover -s tests -v
    python -m unittest tests.test_chain.TestECDSA -v

各モジュールの `self_check()` は「教材としての到達判定」であり、
こちらは「壊れていないことの回帰テスト」。役割が違うので両方置いてある。
"""

from __future__ import annotations

import os
import sys
import unittest
from dataclasses import replace

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "chain"))

import block as blockmod                                          # noqa: E402
import chain as chainmod                                          # noqa: E402
import curve                                                      # noqa: E402
import ecdsa                                                      # noqa: E402
import hashing                                                    # noqa: E402
import merkle                                                     # noqa: E402
import node as nodemod                                            # noqa: E402
import tx as txmod                                                # noqa: E402
from tx import InvalidTx, TxIn, TxOut, Tx, UTXOSet, Wallet, coinbase, transfer  # noqa: E402


FAST = os.environ.get("CHAIN_STUDY_FAST", "1") == "1"


class TestHashing(unittest.TestCase):
    def test_known_vector(self):
        self.assertTrue(hashing.H(b"abc").hex().startswith("ba7816bf8f01cfea"))

    def test_leading_zero_bits(self):
        self.assertEqual(hashing.leading_zero_bits(bytes([0x00, 0x0F])), 12)
        self.assertEqual(hashing.leading_zero_bits(bytes([0x80])), 0)
        self.assertEqual(hashing.leading_zero_bits(bytes(32)), 256)

    def test_avalanche_is_near_half(self):
        avg = hashing.avalanche(trials=300)
        self.assertGreater(avg, 118)
        self.assertLess(avg, 138)

    def test_mine_meets_difficulty(self):
        _, digest, tries = hashing.mine(b"seed", 12)
        self.assertTrue(hashing.meets_difficulty(digest, 12))
        self.assertGreater(tries, 0)


class TestCurve(unittest.TestCase):
    def test_generator_on_curve(self):
        self.assertTrue(curve.SECP256K1.contains(curve.G))

    def test_group_axioms(self):
        G, O = curve.G, curve.infinity()
        self.assertEqual(curve.add(G, O), G)
        self.assertTrue(curve.add(G, curve.neg(G)).is_infinity())
        self.assertEqual(curve.add(curve.add(G, G), G),
                         curve.add(G, curve.add(G, G)))

    def test_generator_order(self):
        self.assertTrue(curve.mul(curve.N, curve.G).is_infinity())
        self.assertEqual(curve.mul(curve.N + 1, curve.G), curve.G)

    def test_scalar_mul_is_homomorphic(self):
        a, b = 987654321, 123456789
        self.assertEqual(curve.mul(a + b, curve.G),
                         curve.add(curve.mul(a, curve.G), curve.mul(b, curve.G)))

    def test_compression_roundtrip(self):
        for _ in range(5):
            Q = curve.pubkey(curve.gen_privkey())
            packed = curve.compress(Q)
            self.assertEqual(len(packed), 33)
            self.assertEqual(curve.decompress(packed), Q)

    def test_decompress_rejects_off_curve(self):
        # x = 1 は実は曲線上にある（y^2 = 8 が平方剰余）。x = 5 は無い。
        with self.assertRaises(ValueError):
            curve.decompress(bytes([2]) + (5).to_bytes(32, "big"))


class TestECDSA(unittest.TestCase):
    def setUp(self):
        self.d = curve.gen_privkey()
        self.Q = curve.pubkey(self.d)
        self.z = ecdsa.msg_hash(b"pay 10 to bob")

    def test_sign_verify(self):
        self.assertTrue(ecdsa.verify(self.Q, self.z, ecdsa.sign(self.d, self.z)))

    def test_rejects_wrong_message(self):
        sig = ecdsa.sign(self.d, self.z)
        self.assertFalse(ecdsa.verify(self.Q, ecdsa.msg_hash(b"pay 10 to eve"), sig))

    def test_rejects_wrong_key(self):
        sig = ecdsa.sign(self.d, self.z)
        other = curve.pubkey(curve.gen_privkey())
        self.assertFalse(ecdsa.verify(other, self.z, sig))

    def test_rejects_out_of_range(self):
        sig = ecdsa.sign(self.d, self.z)
        self.assertFalse(ecdsa.verify(self.Q, self.z, ecdsa.Signature(0, sig.s)))
        self.assertFalse(ecdsa.verify(self.Q, self.z, ecdsa.Signature(sig.r, curve.N)))

    def test_low_s_normalization(self):
        for _ in range(10):
            self.assertLessEqual(ecdsa.sign(self.d, self.z).s, curve.N // 2)

    def test_malleability_is_real(self):
        """(r, n-s) も有効。これは仕様どおりの挙動であり、バグではない。"""
        sig = ecdsa.sign(self.d, self.z)
        self.assertTrue(ecdsa.verify(self.Q, self.z, ecdsa.malleate(sig)))

    def test_nonce_reuse_leaks_private_key(self):
        """【攻撃】k を使い回すと秘密鍵が復元できることを保証する。

        これは「直したい不具合」ではなく「再現し続けたい教材」なので、
        意図せず塞がってしまったら気づけるようにテストにしてある。
        """
        k = 0xC0FFEE_BADC0DE
        z1, z2 = ecdsa.msg_hash(b"one"), ecdsa.msg_hash(b"two")
        s1, s2 = ecdsa.sign(self.d, z1, k=k), ecdsa.sign(self.d, z2, k=k)
        self.assertEqual(s1.r, s2.r)
        self.assertEqual(ecdsa.recover_from_nonce_reuse(s1, z1, s2, z2), self.d)

    def test_distinct_nonces_do_not_leak(self):
        z1, z2 = ecdsa.msg_hash(b"one"), ecdsa.msg_hash(b"two")
        s1, s2 = ecdsa.sign(self.d, z1), ecdsa.sign(self.d, z2)
        self.assertNotEqual(s1.r, s2.r)


class TestMerkle(unittest.TestCase):
    def leaves(self, n):
        return [hashing.dH(b"tx" + str(i).encode()) for i in range(n)]

    def test_single_leaf_is_root(self):
        one = self.leaves(1)
        self.assertEqual(merkle.merkle_root(one), one[0])

    def test_proofs_verify_for_all_sizes(self):
        for n in (1, 2, 3, 4, 5, 7, 8, 9, 16, 17, 33):
            leaves = self.leaves(n)
            root = merkle.merkle_root(leaves)
            for i in range(n):
                self.assertTrue(
                    merkle.verify_proof(leaves[i], merkle.merkle_proof(leaves, i), root),
                    f"n={n} i={i}")

    def test_proof_size_is_log2(self):
        self.assertEqual(len(merkle.merkle_proof(self.leaves(1024), 0)), 10)
        self.assertEqual(len(merkle.merkle_proof(self.leaves(4096), 7)), 12)

    def test_tamper_changes_root(self):
        leaves = self.leaves(8)
        root = merkle.merkle_root(leaves)
        leaves[3] = hashing.dH(b"tampered")
        self.assertNotEqual(merkle.merkle_root(leaves), root)

    def test_fake_leaf_fails_proof(self):
        leaves = self.leaves(8)
        proof = merkle.merkle_proof(leaves, 0)
        self.assertFalse(merkle.verify_proof(hashing.dH(b"fake"), proof,
                                             merkle.merkle_root(leaves)))

    def test_cve_2012_2459_is_reproducible(self):
        """【攻撃】[a,b,c] と [a,b,c,c] が同じ根を持つ。

        課題 2 でここを塞いだら、このテストを「塞がったこと」の確認に書き換える。
        """
        a, b, c = self.leaves(3)
        self.assertEqual(merkle.merkle_root([a, b, c]),
                         merkle.merkle_root([a, b, c, c]))


class TestTransactions(unittest.TestCase):
    def setUp(self):
        self.alice, self.bob = Wallet("alice"), Wallet("bob")
        self.utxos = UTXOSet()
        self.cb = coinbase(self.alice.address, 50)
        self.utxos.apply(self.cb)

    def test_balance_is_derived(self):
        self.assertEqual(self.alice.balance(self.utxos), 50)
        self.assertEqual(self.bob.balance(self.utxos), 0)

    def test_transfer_updates_utxo_set(self):
        t = transfer(self.alice, self.utxos, self.bob.address, 30, fee=1)
        self.assertEqual(self.utxos.validate(t), 1)
        self.utxos.apply(t)
        self.assertEqual(self.bob.balance(self.utxos), 30)
        self.assertEqual(self.alice.balance(self.utxos), 19)

    def test_txid_excludes_signature(self):
        """SegWit の要点。署名を差し替えても txid が動かない。"""
        op = txmod.OutPoint(self.cb.txid(), 0)
        unsigned = Tx((TxIn(op),), (TxOut(5, self.bob.address),))
        self.assertEqual(unsigned.txid(), self.alice.sign(unsigned).txid())

    def test_double_spend_rejected(self):
        t = transfer(self.alice, self.utxos, self.bob.address, 30)
        self.utxos.apply(t)
        again = self.alice.sign(Tx((TxIn(txmod.OutPoint(self.cb.txid(), 0)),),
                                   (TxOut(10, self.bob.address),)))
        with self.assertRaises(InvalidTx):
            self.utxos.validate(again)

    def test_stealing_rejected(self):
        op = next(iter(self.utxos.owned_by(self.alice.address)))
        forged = self.bob.sign(Tx((TxIn(op),), (TxOut(5, self.bob.address),)))
        with self.assertRaises(InvalidTx):
            self.utxos.validate(forged)

    def test_inflation_rejected(self):
        op = next(iter(self.utxos.owned_by(self.alice.address)))
        bad = self.alice.sign(Tx((TxIn(op),), (TxOut(999, self.alice.address),)))
        with self.assertRaises(InvalidTx):
            self.utxos.validate(bad)

    def test_duplicate_input_rejected(self):
        op = next(iter(self.utxos.owned_by(self.alice.address)))
        bad = self.alice.sign(Tx((TxIn(op), TxIn(op)), (TxOut(20, self.bob.address),)))
        with self.assertRaises(InvalidTx):
            self.utxos.validate(bad)

    def test_negative_amount_rejected(self):
        op = next(iter(self.utxos.owned_by(self.alice.address)))
        bad = self.alice.sign(Tx((TxIn(op),), (TxOut(-5, self.bob.address),)))
        with self.assertRaises(InvalidTx):
            self.utxos.validate(bad)

    def test_tampered_signature_rejected(self):
        op = next(iter(self.utxos.owned_by(self.alice.address)))
        good = self.alice.sign(Tx((TxIn(op),), (TxOut(5, self.bob.address),)))
        sig = good.inputs[0].sig
        bad = replace(good, inputs=(replace(good.inputs[0],
                                            sig=ecdsa.Signature(sig.r, sig.s ^ 1)),))
        with self.assertRaises(InvalidTx):
            self.utxos.validate(bad)


class TestBlock(unittest.TestCase):
    def test_mined_block_has_valid_pow(self):
        w = Wallet("m")
        blk = blockmod.build(blockmod.GENESIS_PREV, [coinbase(w.address, 50)], 10)
        mined, tries = blockmod.mine(blk)
        self.assertTrue(mined.header.is_valid_pow())
        self.assertTrue(mined.merkle_ok())
        self.assertGreaterEqual(tries, 1)

    def test_header_tweak_breaks_pow(self):
        w = Wallet("m")
        mined, _ = blockmod.mine(
            blockmod.build(blockmod.GENESIS_PREV, [coinbase(w.address, 50)], 10))
        tweaked = replace(mined.header, timestamp=mined.header.timestamp + 1)
        self.assertFalse(tweaked.is_valid_pow())

    def test_swapped_tx_breaks_merkle(self):
        w, thief = Wallet("m"), Wallet("t")
        mined, _ = blockmod.mine(
            blockmod.build(blockmod.GENESIS_PREV, [coinbase(w.address, 50)], 10))
        self.assertFalse(replace(mined, txs=(coinbase(thief.address, 50),)).merkle_ok())

    def test_header_is_fixed_size(self):
        w = Wallet("m")
        blk = blockmod.build(blockmod.GENESIS_PREV, [coinbase(w.address, 50)], 8)
        self.assertEqual(len(blk.header.to_bytes()), 84)


class TestChain(unittest.TestCase):
    def setUp(self):
        self.miner, self.alice = Wallet("miner"), Wallet("alice")
        self.bc = chainmod.Blockchain(difficulty=8)
        self.bc.add(self.bc.mine_block(self.miner))

    def test_extends(self):
        self.bc.add(self.bc.mine_block(self.miner))
        self.assertEqual(self.bc.height(), 1)
        self.assertEqual(self.miner.balance(self.bc.utxos), 2 * chainmod.REWARD)

    def test_fees_go_to_coinbase(self):
        t = transfer(self.miner, self.bc.utxos, self.alice.address, 20, fee=3)
        self.bc.add(self.bc.mine_block(self.miner, [t]))
        self.assertEqual(self.bc.blocks[self.bc.tip].txs[0].total_out(),
                         chainmod.REWARD + 3)

    def test_rejects_bad_pow(self):
        blk = self.bc.mine_block(self.miner)
        bad = replace(blk, header=replace(blk.header, nonce=blk.header.nonce + 1))
        with self.assertRaises(InvalidTx):
            self.bc.add(bad)

    def test_rejects_overpaying_coinbase(self):
        greedy = coinbase(self.miner.address, chainmod.REWARD * 10, tag=b"greedy")
        blk, _ = blockmod.mine(blockmod.build(self.bc.tip, [greedy], self.bc.difficulty))
        with self.assertRaises(InvalidTx):
            self.bc.add(blk)

    def test_rejects_unknown_parent(self):
        orphan_parent = bytes(range(32))
        blk, _ = blockmod.mine(blockmod.build(
            orphan_parent, [coinbase(self.miner.address, chainmod.REWARD, tag=b"x")],
            self.bc.difficulty))
        with self.assertRaises(InvalidTx):
            self.bc.add(blk)

    def test_fork_does_not_move_tip(self):
        self.bc.add(self.bc.mine_block(self.miner))
        tip = self.bc.tip
        side = self.bc.mine_block(self.miner,
                                  on=self.bc.blocks[tip].header.prev_hash)
        self.assertEqual(self.bc.add(side).status, "fork")
        self.assertEqual(self.bc.tip, tip)

    def test_heavier_branch_triggers_reorg(self):
        self.bc.add(self.bc.mine_block(self.miner))
        fork_point = self.bc.blocks[self.bc.tip].header.prev_hash
        side = self.bc.mine_block(self.miner, on=fork_point)
        self.bc.add(side)
        side2 = self.bc.mine_block(self.miner, on=side.hash())
        self.assertEqual(self.bc.add(side2).status, "reorg")
        self.assertEqual(self.bc.tip, side2.hash())

    def test_reorg_undoes_a_confirmed_payment(self):
        """【攻撃】確認済みの支払いが、より重い枝で消える。"""
        merchant = Wallet("merchant")
        seed = transfer(self.miner, self.bc.utxos, self.alice.address, 50)
        self.bc.add(self.bc.mine_block(self.miner, [seed]))

        payment = transfer(self.alice, self.bc.utxos, merchant.address, 50)
        self.bc.add(self.bc.mine_block(self.miner, [payment]))
        fork_point = self.bc.blocks[self.bc.tip].header.prev_hash
        self.bc.add(self.bc.mine_block(self.miner))
        self.assertEqual(merchant.balance(self.bc.utxos), 50)

        self_pay = transfer(self.alice, self.bc.utxo_for(fork_point),
                            self.alice.address, 50)
        tip = fork_point
        for i in range(3):
            blk = self.bc.mine_block(self.alice, [self_pay] if i == 0 else [], on=tip)
            self.bc.add(blk)
            tip = blk.hash()

        self.assertEqual(self.bc.tip, tip)
        self.assertFalse(self.bc.contains_tx(payment.txid()))
        self.assertEqual(merchant.balance(self.bc.utxos), 0)

    def test_nakamoto_probability(self):
        self.assertEqual(chainmod.attacker_success_probability(0.5, 100), 1.0)
        self.assertEqual(chainmod.attacker_success_probability(0.1, 0), 1.0)
        self.assertLess(chainmod.attacker_success_probability(0.1, 6), 1e-3)
        # z が増えれば単調に減る
        probs = [chainmod.attacker_success_probability(0.25, z) for z in range(1, 12)]
        self.assertEqual(probs, sorted(probs, reverse=True))


class TestNetwork(unittest.TestCase):
    def test_zero_latency_never_forks(self):
        net = nodemod.Network(node_count=4, difficulty=8, latency=0.0, seed=5)
        net.run(15)
        net.settle()
        st = net.stats()
        self.assertEqual(st["orphans"], 0)
        self.assertTrue(st["converged"])

    def test_high_latency_creates_orphans(self):
        net = nodemod.Network(node_count=5, difficulty=8, latency=25.0,
                              block_interval=30.0, seed=11)
        net.run(30)
        net.settle()
        self.assertGreater(net.stats()["orphans"], 0)

    def test_all_nodes_converge_after_settling(self):
        net = nodemod.Network(node_count=4, difficulty=8, latency=8.0,
                              block_interval=30.0, seed=13)
        net.run(25)
        net.settle()
        self.assertTrue(net.stats()["converged"])
        tips = {n.chain.tip for n in net.nodes}
        self.assertEqual(len(tips), 1)

    def test_transaction_propagates_and_confirms(self):
        net = nodemod.Network(node_count=3, difficulty=8, latency=1.0, seed=17)
        net.run(3)
        net.settle()
        miner = max(net.nodes, key=lambda n: n.mined)
        bob = net.wallet("bob")
        t = transfer(miner.wallet, miner.chain.utxos, bob.address, 10, fee=1)
        net.submit_tx(t, origin=miner.id)
        net.run(6)
        net.settle()
        self.assertTrue(net.nodes[0].chain.contains_tx(t.txid()))
        self.assertEqual(bob.balance(net.nodes[0].chain.utxos), 10)

    def test_orphaned_txs_return_to_mempool(self):
        """リオーグで巻き戻された tx が mempool に戻ること。

        戻し忘れると送金が静かに消える。実装で最も間違えやすい箇所。
        """
        net = nodemod.Network(node_count=2, difficulty=8, latency=0.0, seed=23)
        net.run(2)
        net.settle()
        n0 = net.nodes[0]
        bob = net.wallet("bob")
        t = transfer(n0.wallet, n0.chain.utxos, bob.address, 5, fee=1)
        n0.receive_tx(t)

        blk = n0.chain.mine_block(n0.wallet, [t])
        n0.chain.add(blk)
        n0._resync_mempool()
        self.assertNotIn(t.txid(), n0.mempool)          # 取り込まれたので消える

        # その枝より重い枝を後から与えてリオーグさせる
        fork_point = blk.header.prev_hash
        tip = fork_point
        for _ in range(2):
            b = n0.chain.mine_block(net.nodes[1].wallet, [], on=tip)
            n0.chain.add(b)
            tip = b.hash()
        n0._resync_mempool()

        self.assertEqual(n0.chain.tip, tip)
        self.assertFalse(n0.chain.contains_tx(t.txid()))
        self.assertIn(t.txid(), n0.mempool, "巻き戻された tx が mempool に戻っていない")


@unittest.skipIf(FAST, "CHAIN_STUDY_FAST=0 で有効化（数十秒かかる）")
class TestSlow(unittest.TestCase):
    def test_pow_tries_match_2_to_the_d(self):
        """試行回数の平均が 2^d の 0.5〜2 倍に収まる（幾何分布なので幅を持たせる）。"""
        d, trials = 14, 30
        total = sum(hashing.mine(b"s%d" % i, d)[2] for i in range(trials))
        ratio = (total / trials) / 2**d
        self.assertGreater(ratio, 0.5)
        self.assertLess(ratio, 2.0)

    def test_orphan_rate_increases_with_latency(self):
        rates = []
        for ratio in (0.0, 0.1, 0.3, 0.6):
            net = nodemod.Network(node_count=6, difficulty=8, latency=30.0 * ratio,
                                  block_interval=30.0, seed=1234)
            net.run(60)
            net.settle()
            rates.append(net.stats()["orphan_rate"])
        self.assertEqual(rates, sorted(rates))


if __name__ == "__main__":
    unittest.main(verbosity=2)
