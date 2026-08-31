"""
Phase 5: トランザクションと UTXO — 「残高」は存在しない

なぜ必要か
----------
素朴に考えると口座に残高を持たせたくなる。Bitcoin はそうしていない。
あるのは「まだ使われていない出力 (Unspent TX Output = UTXO)」の集合だけ。

    tx は「どの UTXO を消して、どんな UTXO を作るか」の宣言でしかない。
    残高とは「自分が鍵を持つ UTXO の合計」という導出値にすぎない。

なぜこの設計か:
    - 二重支払いの判定が「その UTXO が集合にまだ在るか」だけで済む
    - 履歴が明示的にリンクするので、検証が局所的になる
    - 並列検証しやすい（口座残高モデルは順序に依存する）

ここで扱う検証ルールは 5 本だけ。
    1. 入力が指す UTXO が実在するか
    2. その UTXO の宛先の鍵で署名されているか
    3. 入力合計 >= 出力合計 か（差額は手数料）
    4. 同じ tx の中で同じ UTXO を 2 回使っていないか
    5. 額が負でないか

到達点
------
- 送金が通り、UTXO 集合が正しく更新されることを確認する
- 二重支払い・署名偽造・額の水増しが、上のルールのどれで落ちるかを見る
- txid に署名を含めないと何が嬉しいか（= SegWit の要点）を理解する
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace

import curve
import ecdsa
from ecdsa import Signature
from hashing import dH


# ---------------------------------------------------------------- アドレス

def address_of(pubkey_compressed: bytes) -> bytes:
    """公開鍵からアドレス（20 バイト）を作る。

    Bitcoin は RIPEMD160(SHA256(pubkey))。ここでは標準ライブラリだけで
    済ませたいので SHA256 の 2 段掛けを 20 バイトに切って使う。
    役割は同じ「公開鍵のコミットメント」。

    なぜ公開鍵をそのまま晒さないのか:
      使うまで公開鍵が表に出ないので、量子計算機で ECDLP が破れる将来でも
      「一度も使っていないアドレス」はハッシュの原像困難性で守られる。
    """
    return dH(pubkey_compressed)[:20]


def addr_str(addr: bytes) -> str:
    return addr.hex()[:12]


# ---------------------------------------------------------------- 構造

@dataclass(frozen=True)
class OutPoint:
    """過去の tx の何番目の出力か、という指差し。"""
    txid: bytes
    index: int

    def __repr__(self) -> str:
        return f"{self.txid[:4].hex()}:{self.index}"


@dataclass(frozen=True)
class TxOut:
    """出力 = 「この額を、このアドレスの持ち主だけが使える」という約束。"""
    amount: int
    address: bytes

    def __repr__(self) -> str:
        return f"TxOut({self.amount} -> {addr_str(self.address)})"


@dataclass(frozen=True)
class TxIn:
    """入力 = 過去の UTXO の指差し + それを使う権利の証明。"""
    prev: OutPoint
    pubkey: bytes = b""                 # 33 バイト圧縮公開鍵
    sig: Signature | None = None

    def __repr__(self) -> str:
        return f"TxIn({self.prev})"


@dataclass(frozen=True)
class Tx:
    inputs: tuple[TxIn, ...]
    outputs: tuple[TxOut, ...]

    def is_coinbase(self) -> bool:
        """新規発行 tx。入力を持たない特別な tx で、無から額を作る。"""
        return len(self.inputs) == 0

    def core_bytes(self) -> bytes:
        """署名を含まない、tx の骨格の直列化。

        ここに署名を入れないのが要点。署名は「この骨格に対する承認」であって
        骨格の一部ではない。含めてしまうと、署名が決まらないと骨格が決まらず、
        骨格が決まらないと署名できない、という循環になる。
        """
        parts = [len(self.inputs).to_bytes(4, "big")]
        for i in self.inputs:
            parts.append(i.prev.txid + i.prev.index.to_bytes(4, "big"))
        parts.append(len(self.outputs).to_bytes(4, "big"))
        for o in self.outputs:
            # signed=True は必須。負の額は「検証で弾く」対象であって、
            # 「直列化で例外を投げる」対象ではない。ここで落ちると、
            # 不正 tx を投げるだけでノードを落とせてしまう（DoS）。
            # パーサと直列化は、どんな入力に対しても全域でなければならない。
            parts.append(o.amount.to_bytes(8, "big", signed=True) + o.address)
        return b"".join(parts)

    def txid(self) -> bytes:
        """tx の識別子。署名を含めない。

        Bitcoin は当初これに署名まで含めていた。すると Phase 3 で見た延性
        （s を n-s に変えても有効）で、第三者が txid を書き換えられてしまう。
        署名を id の計算から外すのが SegWit の中心的なアイデアで、
        このリポジトリでは最初からそう作っている。
        """
        return dH(self.core_bytes())

    def sighash(self) -> int:
        """署名対象のスカラー z。

        Bitcoin には SIGHASH_ALL / SINGLE / ANYONECANPAY といった
        「tx のどこに署名するか」を選ぶフラグがあるが、ここでは
        常に全体（= SIGHASH_ALL 相当）に署名する。
        """
        return int.from_bytes(dH(self.core_bytes()), "big") % curve.N

    def total_out(self) -> int:
        return sum(o.amount for o in self.outputs)

    def __repr__(self) -> str:
        kind = "coinbase" if self.is_coinbase() else f"{len(self.inputs)} in"
        return f"Tx({self.txid()[:4].hex()} {kind} -> {len(self.outputs)} out)"


# ---------------------------------------------------------------- ウォレット

@dataclass
class Wallet:
    """鍵の入れ物。「残高」は持たず、必要なとき UTXO 集合に問い合わせる。"""
    name: str
    priv: int = field(default_factory=curve.gen_privkey)

    @property
    def pub(self) -> bytes:
        return curve.compress(curve.pubkey(self.priv))

    @property
    def address(self) -> bytes:
        return address_of(self.pub)

    def balance(self, utxos: "UTXOSet") -> int:
        return sum(o.amount for o in utxos.owned_by(self.address).values())

    def sign(self, tx: Tx) -> Tx:
        """この tx の全入力に自分の署名を入れる。

        署名対象は sighash()、つまり署名を除いた骨格。だから
        「署名を入れたら sighash が変わる」ということが起きない。
        """
        z = tx.sighash()
        signed = tuple(
            replace(i, pubkey=self.pub, sig=ecdsa.sign(self.priv, z))
            for i in tx.inputs
        )
        return replace(tx, inputs=signed)


# ---------------------------------------------------------------- UTXO 集合

class InvalidTx(Exception):
    pass


class UTXOSet:
    """まだ使われていない出力の集合。これがチェーンの「状態」のすべて。"""

    def __init__(self) -> None:
        self.utxos: dict[OutPoint, TxOut] = {}

    def copy(self) -> "UTXOSet":
        new = UTXOSet()
        new.utxos = dict(self.utxos)
        return new

    def owned_by(self, address: bytes) -> dict[OutPoint, TxOut]:
        return {op: o for op, o in self.utxos.items() if o.address == address}

    def validate(self, tx: Tx, coinbase_reward: int | None = None) -> int:
        """tx を検証し、手数料を返す。落ちる場合は InvalidTx。"""
        if any(o.amount < 0 for o in tx.outputs):
            raise InvalidTx("出力額が負")                       # ルール 5

        if tx.is_coinbase():
            if coinbase_reward is None:
                raise InvalidTx("coinbase をブロック外で検証しようとした")
            if tx.total_out() > coinbase_reward:
                raise InvalidTx(
                    f"発行しすぎ: {tx.total_out()} > 許容 {coinbase_reward}")
            return 0

        seen: set[OutPoint] = set()
        total_in = 0
        z = tx.sighash()

        for txin in tx.inputs:
            if txin.prev in seen:                               # ルール 4
                raise InvalidTx(f"同一 tx 内で {txin.prev} を二重に使用")
            seen.add(txin.prev)

            prev_out = self.utxos.get(txin.prev)
            if prev_out is None:                                # ルール 1
                raise InvalidTx(f"存在しない UTXO を参照: {txin.prev}"
                                "（使用済み、または最初から無い = 二重支払い）")

            if address_of(txin.pubkey) != prev_out.address:      # ルール 2-a
                raise InvalidTx(f"公開鍵が宛先アドレスと一致しない: {txin.prev}")

            if txin.sig is None:
                raise InvalidTx(f"署名がない: {txin.prev}")

            Q = curve.decompress(txin.pubkey)
            if not ecdsa.verify(Q, z, txin.sig):                 # ルール 2-b
                raise InvalidTx(f"署名が無効: {txin.prev}")

            total_in += prev_out.amount

        if total_in < tx.total_out():                            # ルール 3
            raise InvalidTx(f"入力不足: 入力 {total_in} < 出力 {tx.total_out()}")

        return total_in - tx.total_out()                          # 手数料

    def apply(self, tx: Tx) -> None:
        """検証済みの tx を状態に反映する。入力を消し、出力を足す。"""
        for txin in tx.inputs:
            del self.utxos[txin.prev]
        txid = tx.txid()
        for i, out in enumerate(tx.outputs):
            self.utxos[OutPoint(txid, i)] = out

    def __len__(self) -> int:
        return len(self.utxos)


# ---------------------------------------------------------------- 組み立て補助

def coinbase(address: bytes, amount: int, tag: bytes = b"") -> Tx:
    """新規発行 tx。入力を持たず、無から額を作る唯一の tx。

    入力がないので、同じ (address, amount) だと txid が衝突してしまう。
    Bitcoin は coinbase に任意データ欄を置き、そこにブロック高を書いて
    一意性を確保している（BIP34）。ここでは tag をそのまま額 0 の
    ダミー出力にして同じ役割を持たせる。
    """
    outs = [TxOut(amount, address)]
    if tag:
        outs.append(TxOut(0, address_of(tag)))    # 一意性のためだけの目印
    return Tx(inputs=(), outputs=tuple(outs))


def transfer(sender: Wallet, utxos: UTXOSet, to_address: bytes,
             amount: int, fee: int = 0) -> Tx:
    """送金 tx を組み立てて署名する。おつりは自分に返す。"""
    owned = sorted(sender.owned(utxos).items(), key=lambda kv: -kv[1].amount) \
        if hasattr(sender, "owned") else \
        sorted(utxos.owned_by(sender.address).items(), key=lambda kv: -kv[1].amount)

    picked, total = [], 0
    for op, out in owned:
        picked.append(op)
        total += out.amount
        if total >= amount + fee:
            break
    if total < amount + fee:
        raise InvalidTx(f"{sender.name} の残高不足: {total} < {amount + fee}")

    outputs = [TxOut(amount, to_address)]
    change = total - amount - fee
    if change > 0:
        outputs.append(TxOut(change, sender.address))

    tx = Tx(inputs=tuple(TxIn(op) for op in picked), outputs=tuple(outputs))
    return sender.sign(tx)


# ---------------------------------------------------------------- 自己確認

def self_check() -> None:
    alice, bob = Wallet("alice"), Wallet("bob")
    utxos = UTXOSet()

    cb = coinbase(alice.address, 50)
    assert utxos.validate(cb, coinbase_reward=50) == 0
    utxos.apply(cb)
    assert alice.balance(utxos) == 50

    # 正常な送金
    tx = transfer(alice, utxos, bob.address, 30, fee=1)
    assert utxos.validate(tx) == 1                       # 手数料 1
    utxos.apply(tx)
    assert bob.balance(utxos) == 30
    assert alice.balance(utxos) == 19                    # 50 - 30 - 1

    # 二重支払い: 使い終わった UTXO をもう一度指す
    spent = OutPoint(cb.txid(), 0)
    dbl = alice.sign(Tx(inputs=(TxIn(spent),), outputs=(TxOut(10, bob.address),)))
    try:
        utxos.validate(dbl)
        raise AssertionError("二重支払いが通ってしまった")
    except InvalidTx:
        pass

    # 署名の偽造: bob が alice の UTXO を使おうとする
    alice_op = next(iter(utxos.owned_by(alice.address)))
    forged = bob.sign(Tx(inputs=(TxIn(alice_op),), outputs=(TxOut(5, bob.address),)))
    try:
        utxos.validate(forged)
        raise AssertionError("他人の UTXO が使えてしまった")
    except InvalidTx:
        pass

    # 水増し: 入力 19 に対して出力 1000
    inflate = alice.sign(Tx(inputs=(TxIn(alice_op),),
                            outputs=(TxOut(1000, alice.address),)))
    try:
        utxos.validate(inflate)
        raise AssertionError("無から金が生まれた")
    except InvalidTx:
        pass

    # 署名を付けても txid は変わらない（= 延性が txid に効かない）
    unsigned = Tx(inputs=(TxIn(alice_op),), outputs=(TxOut(5, bob.address),))
    assert unsigned.txid() == alice.sign(unsigned).txid()

    print("  [ok] tx.py 自己確認 通過")


def demo() -> None:
    alice, bob, carol = Wallet("Alice"), Wallet("Bob"), Wallet("Carol")
    utxos = UTXOSet()

    print("\n-- 観察 1: 残高は UTXO の合計として『出てくる』 ----------------")
    cb = coinbase(alice.address, 50)
    utxos.apply(cb)
    print(f"    coinbase: 50 -> {alice.name}({addr_str(alice.address)})")
    for w in (alice, bob, carol):
        print(f"    {w.name:6} 残高 {w.balance(utxos):>3}  "
              f"(所有 UTXO {len(utxos.owned_by(w.address))} 個)")

    print("\n-- 観察 2: 送金は UTXO の消滅と生成 ----------------------------")
    tx = transfer(alice, utxos, bob.address, 30, fee=1)
    fee = utxos.validate(tx)
    print(f"    tx = {tx}")
    print(f"    入力: {list(tx.inputs)}   ← 50 の UTXO を 1 つ消す")
    print(f"    出力: {list(tx.outputs)}  ← Bob に 30、おつり 19 を自分に")
    print(f"    手数料 = {fee}（入力合計 - 出力合計。誰にも割り当てない差額）")
    utxos.apply(tx)
    for w in (alice, bob, carol):
        print(f"    {w.name:6} 残高 {w.balance(utxos):>3}")
    print("    → 「Alice の残高を 30 減らす」という操作はどこにもない。")
    print("      50 の UTXO が消え、30 と 19 の UTXO が生まれただけ。")

    print("\n-- 観察 3: 不正な tx が、どのルールで落ちるか ------------------")
    cases = []

    spent = OutPoint(cb.txid(), 0)
    cases.append(("二重支払い（使用済み UTXO を再指定）",
                  alice.sign(Tx((TxIn(spent),), (TxOut(10, carol.address),)))))

    alice_op = next(iter(utxos.owned_by(alice.address)))
    cases.append(("他人の UTXO を自分の鍵で使う",
                  bob.sign(Tx((TxIn(alice_op),), (TxOut(5, bob.address),)))))

    cases.append(("入力より多く出力する（水増し）",
                  alice.sign(Tx((TxIn(alice_op),), (TxOut(999, alice.address),)))))

    cases.append(("同じ入力を 1 つの tx で 2 回使う",
                  alice.sign(Tx((TxIn(alice_op), TxIn(alice_op)),
                                (TxOut(20, alice.address),)))))

    good = alice.sign(Tx((TxIn(alice_op),), (TxOut(5, carol.address),)))
    bad_sig = replace(good, inputs=(replace(good.inputs[0],
                                            sig=Signature(good.inputs[0].sig.r,
                                                          good.inputs[0].sig.s ^ 1)),))
    cases.append(("署名を 1 ビット改ざん", bad_sig))

    for label, bad in cases:
        try:
            utxos.validate(bad)
            print(f"    [!!] {label:<34} → 通ってしまった")
        except InvalidTx as e:
            print(f"    [拒否] {label:<32} → {e}")

    print("""
    → 検証は 5 本のルールの積み重ねでしかない。難しい判断は 1 つもない。
      「難しさ」は全部、どの履歴を正とするか（Phase 7 の合意）に押し出されている。
""")


if __name__ == "__main__":
    from util import enable_utf8_stdout

    enable_utf8_stdout()
    self_check()
    demo()
