"""
課題のテスト — 解くと skipped が ok に変わる

    python -m unittest tests.test_exercises -v

各課題は EXERCISES.md で関数名とシグネチャを決めてある。
実装されていない間はスキップされ、スキップ理由に「何を作れば有効になるか」が出る。

なぜこうするか
--------------
「対策を書け」とだけ言われても、正解かどうかが自分で判定できない。
先に判定条件（= テスト）を置いておけば、詰まっているのが理解なのか実装なのかが
自分で切り分けられる。ibe-study の「到達判定」と同じ考え方を、
実行できる形にしただけ。
"""

from __future__ import annotations

import hashlib
import importlib
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "chain"))

import block as blockmod                                          # noqa: E402
import chain as chainmod                                          # noqa: E402
import curve                                                      # noqa: E402
import ecdsa                                                      # noqa: E402
import hashing                                                    # noqa: E402
import merkle                                                     # noqa: E402


def missing(mod, *names: str) -> bool:
    return not all(hasattr(mod, n) for n in names)


def optional_module(name: str):
    try:
        return importlib.import_module(name)
    except ImportError:
        return None


schnorr = optional_module("schnorr")


# ---------------------------------------------------------------- 課題 1

@unittest.skipIf(missing(ecdsa, "sign_rfc6979"),
                 "課題 1 未着手: chain/ecdsa.py に sign_rfc6979(d, z) を実装すると有効になります")
class TestExercise1RFC6979(unittest.TestCase):
    """決定的 ECDSA。乱数源が壊れても秘密鍵が漏れないようにする。"""

    def setUp(self):
        self.d = curve.gen_privkey()
        self.Q = curve.pubkey(self.d)
        self.z1 = ecdsa.msg_hash(b"pay 10 to bob")
        self.z2 = ecdsa.msg_hash(b"pay 10 to carol")

    def test_deterministic(self):
        a = ecdsa.sign_rfc6979(self.d, self.z1)
        b = ecdsa.sign_rfc6979(self.d, self.z1)
        self.assertEqual((a.r, a.s), (b.r, b.s), "同じ (d, z) で署名が変わっています")

    def test_different_message_different_r(self):
        a = ecdsa.sign_rfc6979(self.d, self.z1)
        b = ecdsa.sign_rfc6979(self.d, self.z2)
        self.assertNotEqual(a.r, b.r, "違う z なのに r が同じ = k を使い回しています")

    def test_signature_verifies(self):
        self.assertTrue(ecdsa.verify(self.Q, self.z1,
                                     ecdsa.sign_rfc6979(self.d, self.z1)))

    def test_low_s(self):
        self.assertLessEqual(ecdsa.sign_rfc6979(self.d, self.z1).s, curve.N // 2)

    def test_nonce_reuse_attack_no_longer_applies(self):
        """r が違うので、そもそも復元式が使えない。"""
        a = ecdsa.sign_rfc6979(self.d, self.z1)
        b = ecdsa.sign_rfc6979(self.d, self.z2)
        with self.assertRaises(AssertionError):
            ecdsa.recover_from_nonce_reuse(a, self.z1, b, self.z2)


# ---------------------------------------------------------------- 課題 2

@unittest.skipIf(missing(merkle, "safe_merkle_root", "safe_merkle_proof",
                         "verify_safe_proof"),
                 "課題 2 未着手: chain/merkle.py に safe_merkle_root / "
                 "safe_merkle_proof / verify_safe_proof を実装すると有効になります")
class TestExercise2DomainSeparation(unittest.TestCase):
    """CVE-2012-2459 をドメイン分離で塞ぐ。"""

    def leaves(self, n):
        return [hashing.dH(b"tx" + str(i).encode()) for i in range(n)]

    def test_cve_is_closed(self):
        a, b, c = self.leaves(3)
        self.assertNotEqual(merkle.safe_merkle_root([a, b, c]),
                            merkle.safe_merkle_root([a, b, c, c]),
                            "まだ [a,b,c] と [a,b,c,c] の根が一致します")

    def test_original_still_vulnerable(self):
        """元の実装は攻撃の再現用に残しておく。"""
        a, b, c = self.leaves(3)
        self.assertEqual(merkle.merkle_root([a, b, c]),
                         merkle.merkle_root([a, b, c, c]))

    def test_proofs_verify_for_all_sizes(self):
        for n in (1, 2, 3, 4, 5, 7, 8, 9, 16, 17, 33):
            leaves = self.leaves(n)
            root = merkle.safe_merkle_root(leaves)
            for i in range(n):
                proof = merkle.safe_merkle_proof(leaves, i)
                self.assertTrue(merkle.verify_safe_proof(leaves[i], proof, root),
                                f"n={n} i={i} で証明が通りません")

    def test_fake_leaf_fails(self):
        leaves = self.leaves(8)
        proof = merkle.safe_merkle_proof(leaves, 0)
        self.assertFalse(merkle.verify_safe_proof(
            hashing.dH(b"fake"), proof, merkle.safe_merkle_root(leaves)))

    def test_leaf_hash_differs_from_node_hash(self):
        """葉と内部ノードでハッシュの入力空間が分かれているか。

        1 枚だけの木の根が、その葉そのものだったら分離できていない。
        """
        one = self.leaves(1)
        self.assertNotEqual(merkle.safe_merkle_root(one), one[0],
                            "葉がそのまま根になっています（ドメイン分離が効いていません）")


# ---------------------------------------------------------------- 課題 3

@unittest.skipIf(missing(chainmod, "retarget"),
                 "課題 3 未着手: chain/chain.py に retarget(...) を実装すると有効になります")
class TestExercise3Retarget(unittest.TestCase):
    """難易度の自動調整。"""

    def test_too_fast_raises_difficulty(self):
        self.assertEqual(chainmod.retarget(14, 300, 600), 15)

    def test_too_slow_lowers_difficulty(self):
        self.assertEqual(chainmod.retarget(14, 1200, 600), 13)

    def test_on_target_is_unchanged(self):
        self.assertEqual(chainmod.retarget(14, 600, 600), 14)

    def test_step_is_clamped(self):
        self.assertEqual(chainmod.retarget(14, 1, 600, max_step=2), 16)
        self.assertEqual(chainmod.retarget(14, 10**9, 600, max_step=2), 12)

    def test_never_below_one(self):
        self.assertGreaterEqual(chainmod.retarget(1, 10**9, 600), 1)

    def test_doubling_hashrate_costs_one_bit(self):
        """ハッシュ力が 2 倍 = 半分の時間で掘れる = 難易度 +1 ビット。"""
        for d in (10, 14, 20):
            self.assertEqual(chainmod.retarget(d, 600, 1200), d + 1)


# ---------------------------------------------------------------- 課題 4

@unittest.skipIf(missing(blockmod, "timestamp_ok"),
                 "課題 4 未着手: chain/block.py に timestamp_ok(...) を実装すると有効になります")
class TestExercise4Timestamp(unittest.TestCase):
    """time warp 攻撃を塞ぐ 2 つの規則。"""

    def setUp(self):
        self.now = 1_000_000
        self.recent = [self.now - 60 * i for i in range(11)]   # 中央値 = now-300

    def test_accepts_reasonable(self):
        self.assertTrue(blockmod.timestamp_ok(self.now, self.recent, self.now))

    def test_rejects_too_far_future(self):
        self.assertFalse(blockmod.timestamp_ok(
            self.now + 3 * 60 * 60, self.recent, self.now))

    def test_rejects_at_or_before_median(self):
        median = sorted(self.recent)[len(self.recent) // 2]
        self.assertFalse(blockmod.timestamp_ok(median, self.recent, self.now))
        self.assertFalse(blockmod.timestamp_ok(median - 1, self.recent, self.now))

    def test_accepts_just_after_median(self):
        median = sorted(self.recent)[len(self.recent) // 2]
        self.assertTrue(blockmod.timestamp_ok(median + 1, self.recent, self.now))

    def test_handles_empty_history(self):
        self.assertTrue(blockmod.timestamp_ok(self.now, [], self.now))

    def test_one_lying_miner_barely_moves_the_floor(self):
        """嘘つきが 1 人混じっても、中央値は隣の正直な値までしか動かない。

        平均だったら 1 つの極端な値で好きなだけ引きずれる。
        中央値なら順位が 1 つずれるだけで、しかも中央値そのものは
        必ず正直な観測値のどれかになる。過去側に中央値を使う理由がこれ。
        """
        for liar_value in (self.now - 10**6, self.now + 10**6):
            liars = list(self.recent)
            liars[0] = liar_value
            median_before = sorted(self.recent)[len(self.recent) // 2]
            median_after = sorted(liars)[len(liars) // 2]
            self.assertIn(median_after, self.recent,
                          "嘘の値そのものが中央値になっています")
            self.assertLessEqual(abs(median_after - median_before), 60,
                                 "中央値が 1 つ分より大きく動いています")


# ---------------------------------------------------------------- 課題 5

@unittest.skipIf(missing(hashing, "sha256_from_scratch"),
                 "課題 5 未着手: chain/hashing.py に sha256_from_scratch(data) を"
                 "実装すると有効になります")
class TestExercise5SHA256(unittest.TestCase):
    """SHA-256 の自作。パディング境界でだいたい間違える。"""

    def check(self, data: bytes):
        self.assertEqual(hashing.sha256_from_scratch(data),
                         hashlib.sha256(data).digest(),
                         f"{len(data)} バイトで一致しません")

    def test_empty(self):
        self.check(b"")

    def test_abc(self):
        self.check(b"abc")

    def test_padding_boundaries(self):
        for n in (54, 55, 56, 57, 63, 64, 65, 119, 120, 128):
            self.check(b"a" * n)

    def test_long_message(self):
        self.check(b"chain-study " * 1000)

    def test_binary_data(self):
        self.check(bytes(range(256)))


# ---------------------------------------------------------------- 課題 6

@unittest.skipIf(schnorr is None,
                 "課題 6 未着手: chain/schnorr.py を作って sign / verify / challenge を"
                 "実装すると有効になります")
class TestExercise6Schnorr(unittest.TestCase):
    """Schnorr 署名。線形性があるので鍵と署名を足せる。"""

    def setUp(self):
        self.d = curve.gen_privkey()
        self.P = curve.pubkey(self.d)
        self.msg = b"transfer 10 coins"

    def test_sign_verify(self):
        self.assertTrue(schnorr.verify(self.P, self.msg,
                                       schnorr.sign(self.d, self.msg)))

    def test_rejects_tampered_message(self):
        sig = schnorr.sign(self.d, self.msg)
        self.assertFalse(schnorr.verify(self.P, b"transfer 999 coins", sig))

    def test_rejects_wrong_key(self):
        sig = schnorr.sign(self.d, self.msg)
        other = curve.pubkey(curve.gen_privkey())
        self.assertFalse(schnorr.verify(other, self.msg, sig))

    def test_linearity(self):
        """署名が足せる。ECDSA では逆元が挟まるのでこれができない。

        d = d1 + d2, P = P1 + P2 に対し、同じ R と e を使えば
        s = s1 + s2 がそのまま合成鍵の署名になる。
        """
        d1, d2 = curve.gen_privkey(), curve.gen_privkey()
        d = (d1 + d2) % curve.N
        P = curve.add(curve.pubkey(d1), curve.pubkey(d2))
        self.assertEqual(P, curve.pubkey(d))

        k1, k2 = curve.gen_privkey(), curve.gen_privkey()
        R = curve.add(curve.mul(k1, curve.G), curve.mul(k2, curve.G))
        e = schnorr.challenge(R, P, self.msg)
        s = ((k1 + e * d1) + (k2 + e * d2)) % curve.N

        self.assertTrue(schnorr.verify(P, self.msg, (R, s)),
                        "個別の署名を足したものが合成鍵の署名になっていません")


if __name__ == "__main__":
    unittest.main(verbosity=2)
