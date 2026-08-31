"""
Phase 2: 楕円曲線 secp256k1 — 「誰のコインか」を決める代数

なぜ必要か
----------
ハッシュだけでは「改ざんされていないこと」しか言えない。
「この送金は確かに本人が承認した」を言うには署名がいる。
Bitcoin / Ethereum の署名は secp256k1 という 1 本の曲線の上で動いている。

    E : y^2 = x^3 + 7   over  F_p,   p = 2^256 - 2^32 - 977

Phase 0 で作った有限体 F_p の上に、点の加法という群構造を乗せる。
群になれば離散対数問題が立ち、離散対数が難しければ秘密鍵が守られる。
構造は Phase 0 の (Z/pZ)* とまったく同じで、演算の書き方が変わるだけ。

方針メモ
--------
アフィン座標で書く。点加算のたびに逆元計算（= 冪乗）が走るので遅いが、
式が教科書のまま読める。速い実装（ヤコビ座標）は roadmap の発展課題。

到達点
------
- 小さい曲線 E(F_97) の点を全部列挙して、群であることを目で見る
- N*G = O （G の位数がちょうど N）を 256 ビットの本物の曲線で確認する
- 公開鍵 = d*G は一瞬、その逆（d を求める）は絶望的、という非対称を再確認する
"""

from __future__ import annotations

import os
from dataclasses import dataclass


# ---------------------------------------------------------------- 曲線パラメータ

# secp256k1
P = 2**256 - 2**32 - 977
A = 0
B = 7
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141  # G の位数


@dataclass(frozen=True)
class Curve:
    """y^2 = x^3 + a*x + b over F_p。"""
    p: int
    a: int
    b: int

    def contains(self, pt: "Point") -> bool:
        if pt.is_infinity():
            return True                      # 無限遠点は定義上いつでも曲線上
        return (pt.y * pt.y - (pt.x**3 + self.a * pt.x + self.b)) % self.p == 0


SECP256K1 = Curve(P, A, B)


@dataclass(frozen=True)
class Point:
    """E 上の点。x = y = None を無限遠点 O（群の単位元）とする。"""
    x: int | None
    y: int | None
    curve: Curve = SECP256K1

    def is_infinity(self) -> bool:
        return self.x is None

    def __repr__(self) -> str:
        if self.is_infinity():
            return "O"
        if self.x > 0xFFFF:
            return f"({self.x:x}..., {self.y:x}...)"
        return f"({self.x}, {self.y})"


def infinity(curve: Curve = SECP256K1) -> Point:
    return Point(None, None, curve)


# ---------------------------------------------------------------- 群演算

def inverse_mod(a: int, p: int) -> int:
    """a の mod p 逆元。Phase 0 では拡張ユークリッドを自前で書いたので、
    ここは pow の 3 引数形に任せる。"""
    return pow(a, -1, p)


def neg(pt: Point) -> Point:
    """-P。x 軸に折り返すだけ。P + (-P) = O。"""
    if pt.is_infinity():
        return pt
    return Point(pt.x, (-pt.y) % pt.curve.p, pt.curve)


def add(p1: Point, p2: Point) -> Point:
    """楕円曲線の点加算（弦・接線法）。

    幾何的には「2 点を通る直線が曲線と交わる第 3 の点を x 軸で折り返す」。
    代数的には傾き s を出して

        x3 = s^2 - x1 - x2,   y3 = s*(x1 - x3) - y1

    s の作り方だけが 2 通りある:
        P != Q  : s = (y2 - y1) / (x2 - x1)      （弦の傾き）
        P == Q  : s = (3*x1^2 + a) / (2*y1)      （接線の傾き = 陰関数微分）
    """
    if p1.is_infinity():
        return p2
    if p2.is_infinity():
        return p1

    curve = p1.curve
    p = curve.p

    if p1.x == p2.x and (p1.y + p2.y) % p == 0:
        return infinity(curve)               # P + (-P) = O

    if p1.x == p2.x:                         # P == Q なので接線
        s = (3 * p1.x * p1.x + curve.a) * inverse_mod(2 * p1.y, p) % p
    else:                                    # P != Q なので弦
        s = (p2.y - p1.y) * inverse_mod(p2.x - p1.x, p) % p

    x3 = (s * s - p1.x - p2.x) % p
    y3 = (s * (p1.x - x3) - p1.y) % p
    return Point(x3, y3, curve)


def mul(k: int, pt: Point) -> Point:
    """スカラー倍 k*P を double-and-add で。

    k を 2 進数で見て、下のビットから「倍にしながら足すか足さないか」。
    ビット長ぶんのループで済むので、256 ビットでも 256 回程度。
    Phase 0 の繰り返し二乗法（冪乗）と同じ骨格。乗法を加法で書き直しただけ。

    注意: この素朴な実装は k のビットパターンで実行時間が変わるため、
    実運用ではサイドチャネル攻撃を受ける。定数時間化は roadmap の課題。
    """
    if pt.is_infinity():
        return infinity(pt.curve)
    if k < 0:
        return mul(-k, neg(pt))

    result = infinity(pt.curve)
    addend = pt
    while k:
        if k & 1:
            result = add(result, addend)
        addend = add(addend, addend)
        k >>= 1
    return result


G = Point(GX, GY, SECP256K1)


# ---------------------------------------------------------------- 鍵と符号化

def gen_privkey() -> int:
    """1 <= d < N の乱数。秘密鍵とはこれだけのもの。"""
    while True:
        d = int.from_bytes(os.urandom(32), "big")
        if 1 <= d < N:
            return d


def pubkey(d: int) -> Point:
    """公開鍵 = d*G。"""
    return mul(d, G)


def compress(pt: Point) -> bytes:
    """圧縮公開鍵（33 バイト）。

    曲線上では x が決まれば y は 2 つ（y と p-y）に絞られる。
    なので y は「偶数か奇数か」の 1 バイトで足りる。65 バイトが 33 バイトになる。
    """
    assert not pt.is_infinity()
    return bytes([2 + (pt.y & 1)]) + pt.x.to_bytes(32, "big")


def decompress(data: bytes, curve: Curve = SECP256K1) -> Point:
    """圧縮公開鍵を復元する。

    y^2 = x^3 + 7 を解く。secp256k1 は p = 3 (mod 4) なので
    平方根は y = (y^2)^((p+1)/4) で一発。
    """
    prefix, x = data[0], int.from_bytes(data[1:], "big")
    y2 = (x**3 + curve.a * x + curve.b) % curve.p
    y = pow(y2, (curve.p + 1) // 4, curve.p)
    if (y * y - y2) % curve.p != 0:
        raise ValueError("曲線上にない x")
    if y & 1 != prefix & 1:
        y = curve.p - y
    return Point(x, y, curve)


# ---------------------------------------------------------------- 自己確認

def self_check() -> None:
    assert SECP256K1.contains(G), "G が曲線上にない"

    # 群の公理を確認する
    O = infinity()
    assert add(G, O) == G                          # 単位元
    assert add(G, neg(G)).is_infinity()            # 逆元
    assert add(add(G, G), G) == add(G, add(G, G))  # 結合則（3G の 2 通りの作り方）
    assert mul(2, G) == add(G, G)
    assert mul(3, G) == add(add(G, G), G)

    # G の位数がちょうど N。「素数位数の巡回群」であることの実測。
    assert mul(N, G).is_infinity(), "N*G != O"
    assert mul(N + 1, G) == G

    # (a+b)*G = a*G + b*G
    a, b = 12345, 67890
    assert mul(a + b, G) == add(mul(a, G), mul(b, G))

    # 圧縮と復元の往復
    d = gen_privkey()
    Q = pubkey(d)
    assert SECP256K1.contains(Q)
    assert decompress(compress(Q)) == Q
    assert len(compress(Q)) == 33

    print("  [ok] curve.py 自己確認 通過")


def small_curve_demo() -> None:
    """小さい曲線で群構造を目で見る。

    256 ビットでは何も観察できない。位数 100 程度なら全点を列挙できる。
    Phase 0 で「位数 11 の群なら全要素が並べられる」とやったのと同じ発想。
    """
    small = Curve(97, 2, 3)                   # y^2 = x^3 + 2x + 3 over F_97
    points = [infinity(small)]
    for x in range(small.p):
        rhs = (x**3 + small.a * x + small.b) % small.p
        for y in range(small.p):
            if y * y % small.p == rhs:
                points.append(Point(x, y, small))

    print("    E: y^2 = x^3 + 2x + 3 over F_97")
    print(f"    曲線上の点の総数（無限遠点込み） = {len(points)}")

    # 生成元を 1 つ選んで、その巡回部分群を全部並べる
    gen = points[1]
    orbit, cur = [], gen
    while True:
        orbit.append(cur)
        cur = add(cur, gen)
        if cur.is_infinity():
            break
    order = len(orbit) + 1
    print(f"    生成元 P = {gen} の位数 = {order}")
    print("    <P> = " + ", ".join(str(pt) for pt in orbit[:6]) + ", ..., O")
    print(f"    → 位数 {order} は群位数 {len(points)} を割り切る（ラグランジュ）:"
          f" {len(points)} / {order} = {len(points) // order}")
    print("      Phase 0 の巡回群で確認したのとまったく同じ構造。")


def demo() -> None:
    print("\n-- 観察 1: 小さい曲線で群を見る --------------------------------")
    small_curve_demo()

    print("\n-- 観察 2: secp256k1 本体 --------------------------------------")
    print(f"    p = {P}")
    print(f"    N = {N}   （G の位数、これも素数）")
    print(f"    G = ({GX:064x},")
    print(f"         {GY:064x})")
    print(f"    N*G = {mul(N, G)}   ← 一周して単位元に戻る")

    print("\n-- 観察 3: 鍵ペアは『掛け算 1 回』でしかない -------------------")
    d = gen_privkey()
    Q = pubkey(d)
    print(f"    秘密鍵 d = {d:064x}")
    print(f"    公開鍵 Q = d*G")
    print(f"      Q.x    = {Q.x:064x}")
    print(f"      圧縮形式 = {compress(Q).hex()}  ({len(compress(Q))} バイト)")
    print("""
    → d から Q は 256 回程度の加算で出る。逆に Q から d を求めるのが
      楕円曲線離散対数問題 (ECDLP)。既知の最良手法でも約 2^128 回かかる。

    → Phase 0 で測った離散対数の壁が、そのままここに立っている。
      「秘密鍵を守る」とは、この 2^128 に賭けるということ。
""")


if __name__ == "__main__":
    from util import enable_utf8_stdout

    enable_utf8_stdout()
    self_check()
    demo()
