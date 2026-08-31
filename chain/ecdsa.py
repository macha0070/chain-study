"""
Phase 3: ECDSA — 「本人が承認した」を数学で言う

なぜ必要か
----------
UTXO を動かせるのは、その UTXO を指定した公開鍵の持ち主だけ。
その「持ち主であること」を、秘密鍵を見せずに証明するのが署名。

署名 (r, s) の作り方は 3 行で書ける。

    k を秘密の乱数として  R = k*G,  r = R.x mod n
    s = k^{-1} (z + r*d) mod n          （z = メッセージのハッシュ、d = 秘密鍵）

検証はこれを解きほぐすだけ。

    u1 = z/s,  u2 = r/s,  R' = u1*G + u2*Q   に対し  R'.x == r か？

なぜ通るか（この 2 行が全部）:
    u1*G + u2*Q = (z/s)*G + (r/s)*(d*G) = ((z + r*d)/s)*G = k*G = R
    最後の等号は s = k^{-1}(z + r*d) を s で解いた (z + r*d)/s = k から。

到達点
------
- 署名が通り、1 ビット改ざんで落ちることを確認する
- 【本題】nonce k を 2 回使い回すと、署名 2 本から秘密鍵が復元できることを
  実際にやる。これは PS3 (2010) と Android Bitcoin ウォレット (2013) を
  実際に破った攻撃であり、「実装が数学を裏切る」典型例
- 署名延性 (malleability): (r, s) が有効なら (r, n-s) も有効。
  この事実が Bitcoin の txid を不安定にし、SegWit を生んだ
"""

from __future__ import annotations

import os
from dataclasses import dataclass

import curve
from curve import G, N, Point, add, mul, pubkey
from hashing import H


@dataclass(frozen=True)
class Signature:
    r: int
    s: int

    def to_bytes(self) -> bytes:
        return self.r.to_bytes(32, "big") + self.s.to_bytes(32, "big")

    @staticmethod
    def from_bytes(data: bytes) -> "Signature":
        return Signature(int.from_bytes(data[:32], "big"),
                         int.from_bytes(data[32:], "big"))

    def __repr__(self) -> str:
        return f"Sig(r={self.r:064x}, s={self.s:064x})"


def msg_hash(msg: bytes) -> int:
    """メッセージを署名対象のスカラー z に落とす。

    ハッシュ値をそのまま整数として見る。n より大きい可能性があるので mod n。
    """
    return int.from_bytes(H(msg), "big") % N


def sign(d: int, z: int, k: int | None = None, low_s: bool = True) -> Signature:
    """秘密鍵 d でスカラー z に署名する。

    k は「一度きりの乱数 (nonce)」。名前のとおり number used once であって、
    ここを外すと秘密鍵が漏れる。テスト目的でのみ外から k を渡せるようにしてある。
    """
    while True:
        if k is None:
            k_try = int.from_bytes(os.urandom(32), "big") % N
        else:
            k_try = k % N
        if k_try == 0:
            continue

        R = mul(k_try, G)
        r = R.x % N
        if r == 0:
            continue

        s = pow(k_try, -1, N) * (z + r * d) % N
        if s == 0:
            continue

        # 延性対策の正規化。s と n-s は両方valid なので、小さい方に寄せる。
        # 外から k を固定されている場合は、実験の意図を壊さないよう触らない。
        if low_s and k is None and s > N // 2:
            s = N - s
        return Signature(r, s)


def verify(Q: Point, z: int, sig: Signature) -> bool:
    """公開鍵 Q で署名を検証する。"""
    if not (1 <= sig.r < N and 1 <= sig.s < N):
        return False
    if Q.is_infinity() or not curve.SECP256K1.contains(Q):
        return False
    if not mul(N, Q).is_infinity():          # Q が位数 n の部分群にいるか
        return False

    s_inv = pow(sig.s, -1, N)
    u1 = z * s_inv % N
    u2 = sig.r * s_inv % N
    R = add(mul(u1, G), mul(u2, Q))
    if R.is_infinity():
        return False
    return R.x % N == sig.r


# ---------------------------------------------------------------- 攻撃

def recover_from_nonce_reuse(sig1: Signature, z1: int,
                             sig2: Signature, z2: int) -> int:
    """同じ k で作られた 2 本の署名から秘密鍵 d を復元する。

    導出:
        s1 = k^{-1}(z1 + r*d),  s2 = k^{-1}(z2 + r*d)      （r は共通、k が同じなので）
        s1 - s2 = k^{-1}(z1 - z2)
            → k = (z1 - z2) / (s1 - s2)
        s1*k = z1 + r*d
            → d = (s1*k - z1) / r

    未知数 2 つ (k, d) に対して式が 2 本。ただの連立一次方程式で、
    2^128 の壁は一切関係なく解ける。
    """
    assert sig1.r == sig2.r, "r が違う = k は使い回されていない"
    r = sig1.r
    k = (z1 - z2) * pow(sig1.s - sig2.s, -1, N) % N
    d = (sig1.s * k - z1) * pow(r, -1, N) % N
    return d


def malleate(sig: Signature) -> Signature:
    """(r, s) から、同じメッセージ・同じ鍵で有効なもう 1 つの署名を作る。

    検証式には R'.x しか出てこない。R と -R は x が同じなので、
    s を n-s に置き換えても検証を通ってしまう。
    秘密鍵を知らない第三者にもできるのが厄介なところ。
    """
    return Signature(sig.r, N - sig.s)


# ---------------------------------------------------------------- 自己確認

def self_check() -> None:
    d = curve.gen_privkey()
    Q = pubkey(d)
    z = msg_hash(b"pay 10 coins to bob")

    sig = sign(d, z)
    assert verify(Q, z, sig), "正しい署名が通らない"

    # メッセージを変えたら落ちる
    assert not verify(Q, msg_hash(b"pay 10 coins to eve"), sig)
    # 別の鍵では通らない
    assert not verify(pubkey(curve.gen_privkey()), z, sig)
    # r か s を 1 ずらしたら落ちる
    assert not verify(Q, z, Signature(sig.r, (sig.s + 1) % N))
    assert not verify(Q, z, Signature((sig.r + 1) % N, sig.s))
    # 範囲外は弾く
    assert not verify(Q, z, Signature(0, sig.s))

    # 延性: n-s に置き換えても通る（= 署名は一意ではない）
    assert verify(Q, z, malleate(sig))

    # nonce 再利用からの鍵復元
    k = 0xDEADBEEF12345678
    z1, z2 = msg_hash(b"tx one"), msg_hash(b"tx two")
    s1, s2 = sign(d, z1, k=k), sign(d, z2, k=k)
    assert recover_from_nonce_reuse(s1, z1, s2, z2) == d

    # 符号化の往復
    assert Signature.from_bytes(sig.to_bytes()) == sig

    print("  [ok] ecdsa.py 自己確認 通過")


def demo() -> None:
    d = curve.gen_privkey()
    Q = pubkey(d)

    print("\n-- 観察 1: 署名と検証 ------------------------------------------")
    msg = b"Alice -> Bob : 10 coins"
    z = msg_hash(msg)
    sig = sign(d, z)
    print(f"    メッセージ = {msg.decode()}")
    print(f"    z (= H(msg) mod n) = {z:064x}")
    print(f"    r = {sig.r:064x}")
    print(f"    s = {sig.s:064x}")
    print(f"    verify(Q, z, sig)                = {verify(Q, z, sig)}")
    tampered = b"Alice -> Eve : 10 coins"
    print(f"    verify(Q, H('...Eve...'), sig)   = "
          f"{verify(Q, msg_hash(tampered), sig)}   ← 宛先を書き換えたら落ちる")
    print("    → 署名は『この 32 バイトのハッシュ』に対して打たれている。")
    print("      だから何に署名させるか（Phase 4 の sighash）が決定的に重要。")

    print("\n-- 観察 2: 署名は一意ではない（延性） --------------------------")
    m = malleate(sig)
    print(f"    元の s     = {sig.s:064x}")
    print(f"    n - s      = {m.s:064x}")
    print(f"    verify(元)   = {verify(Q, z, sig)}")
    print(f"    verify(n-s)  = {verify(Q, z, m)}   ← 秘密鍵なしで別の有効署名が作れる")
    print("    → 署名が変われば tx のハッシュ (txid) も変わる。")
    print("      未承認 tx の txid を第三者が変えられるのが Bitcoin の延性問題で、")
    print("      Mt.Gox の言い訳に使われ、最終的に SegWit（署名を txid の外に出す）")
    print("      を生んだ。対策は low-s 正規化 + 署名を id 計算から外すこと。")

    print("\n-- 観察 3【本題】nonce の使い回しで秘密鍵が落ちる ---------------")
    print("    実装者が k を固定した（あるいは乱数源が壊れていた）とする。")
    k = 0x00000000DEADBEEF_CAFEBABE0000_0001 % N
    z1, z2 = msg_hash(b"tx one"), msg_hash(b"tx two")
    sig1, sig2 = sign(d, z1, k=k), sign(d, z2, k=k)
    print(f"    sig1.r = {sig1.r:064x}")
    print(f"    sig2.r = {sig2.r:064x}")
    print(f"    r が一致 → k を使い回した証拠がチェーン上に公開されている\n")
    recovered = recover_from_nonce_reuse(sig1, z1, sig2, z2)
    print(f"    本物の秘密鍵 d   = {d:064x}")
    print(f"    復元した秘密鍵   = {recovered:064x}")
    print(f"    一致 = {recovered == d}")
    print("""
    → 破るのに要した計算は逆元 2 回。2^128 は一切関係ない。
      曲線もハッシュも無傷のまま、乱数の使い方だけで全額持っていかれる。

    → 現実に起きた:
        PS3 (2010)                 … Sony が k を定数にしていた。署名鍵が公開された。
        Android ウォレット (2013)  … SecureRandom の欠陥で k が衝突し、盗難が発生。

    → 対策は RFC 6979（決定的 ECDSA）。k を乱数ではなく
        k = HMAC(d, z)
      で作る。同じ (d, z) なら同じ k、違う z なら違う k。
      乱数源に依存しなくなるので、そもそも壊れようがない。
      → docs/roadmap.md の発展課題 1 に置いた。
""")


if __name__ == "__main__":
    from util import enable_utf8_stdout

    enable_utf8_stdout()
    self_check()
    demo()
