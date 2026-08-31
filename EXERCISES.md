# 課題集

このリポジトリには、**わざと直していない穴** がいくつも空いている。
攻撃を先に成功させてから塞ぐ、という順番にしてあるからで、
先に対策を書くと「なぜそれが要るのか」が分からないまま通り過ぎてしまう。

穴を塞ぐのがここの課題。

## 進め方

課題ごとに **関数名とシグネチャが決まっている**。それを実装すると、
対応するテストがスキップから実行に変わり、緑になれば完了。

```bash
python -m unittest tests.test_exercises -v
```

まだ手を付けていない課題は、こう出る。

```
test_deterministic (…TestExercise1RFC6979) ... skipped
    '課題 1 未着手: chain/ecdsa.py に sign_rfc6979(d, z) を実装すると有効になります'
```

実装すると `skipped` が `ok` に変わる。**進捗はテストの色で分かる。**

進み具合をまとめて見るには:

```bash
python tools/progress.py
```

---

## 課題 1 — RFC 6979（決定的 ECDSA）

**なぜ**: `ecdsa.sign()` の `k` は `os.urandom` 頼み。乱数源が壊れれば秘密鍵が漏れる。
それを実演したのが `ecdsa.recover_from_nonce_reuse()`。PS3 と Android ウォレットが
現実に落ちた原因でもある。RFC 6979 は `k` を乱数ではなく秘密鍵とメッセージから
HMAC-SHA256 で導出する。乱数を使わないので、そもそも壊れようがない。

**実装するもの** — `chain/ecdsa.py`

```python
def sign_rfc6979(d: int, z: int) -> Signature:
    """RFC 6979 に従って k を決定的に導出し、署名する。"""
```

**要件**
- 同じ `(d, z)` なら、何度呼んでも完全に同じ `(r, s)` が返る
- 違う `z` なら `r` が必ず変わる
- `verify()` を通る
- `low_s` 正規化（`s <= N // 2`）を保つ

**ヒント**: RFC 6979 §3.2 の HMAC_DRBG。`hmac` と `hashlib` は標準ライブラリにある。
V と K を初期化し、`K = HMAC(K, V || 0x00 || int2octets(d) || bits2octets(z))` から始める。

**参考**: RFC 6979 §3.2 / テストベクタは Appendix A.2.5

---

## 課題 2 — マークル木のドメイン分離

**なぜ**: `merkle.merkle_root()` は段の要素数が奇数のとき最後を複製する。
その結果 `[a,b,c]` と `[a,b,c,c]` の根が一致する（CVE-2012-2459）。
根が同じならブロックハッシュも同じなので、攻撃者は正規ブロックを膨らませて配り、
受信ノードに正規ブロックごと invalid と記録させられる。

対策は 2 通りある。

1. **重複段の拒否** — Bitcoin Core が取った対症療法
2. **ドメイン分離** — RFC 6962 (Certificate Transparency) の方式。
   葉は `H(0x00 || leaf)`、内部ノードは `H(0x01 || left || right)`。
   葉と内部ノードでハッシュの入力空間が重ならないので、構造の取り違えが起きない

課題は 2 のほう。原因のほうを消しにいく。

**実装するもの** — `chain/merkle.py`

```python
def safe_merkle_root(leaves: list[bytes]) -> bytes:
    """ドメイン分離つきのマークル根。"""

def safe_merkle_proof(leaves: list[bytes], index: int) -> list[ProofStep]:
    """safe_merkle_root に対応する包含証明。"""

def verify_safe_proof(leaf: bytes, proof: list[ProofStep], root: bytes) -> bool:
    """葉と証明から根を組み立て直して照合する。"""
```

**要件**
- `safe_merkle_root([a,b,c]) != safe_merkle_root([a,b,c,c])`
- 葉が 1〜33 枚のすべてで、全インデックスの証明が通る
- 偽の葉では通らない
- 元の `merkle_root` は残しておく（攻撃の再現に使うため）

**参考**: RFC 6962 §2.1 / CVE-2012-2459

---

## 課題 3 — 難易度の自動調整

**なぜ**: いまは難易度が固定。実際のチェーンはブロック生成間隔を一定に保つため、
定期的に難易度を再計算する（Bitcoin は 2016 ブロックごと、目標 10 分）。
ハッシュ力が 2 倍になったら難易度を 1 ビット上げればつり合う、という関係を
自分で書くと「難易度がビット数である」ことの意味が変わる。

**実装するもの** — `chain/chain.py`

```python
def retarget(current_difficulty: int, actual_span: float,
             target_span: float, max_step: int = 2) -> int:
    """実際にかかった時間から、次の難易度を決める。

    速すぎた（actual < target）なら難易度を上げ、遅すぎたら下げる。
    調整幅は ±max_step ビットに制限する。
    """
```

**要件**
- `retarget(14, 300, 600) == 15` — 目標の半分の時間で掘れた → 1 ビット上げる
- `retarget(14, 1200, 600) == 13` — 2 倍かかった → 1 ビット下げる
- `retarget(14, 600, 600) == 14` — ちょうどなら動かさない
- `retarget(14, 1, 600) == 16` — どんなに速くても `max_step` を超えない
- 難易度は 1 以上

**考えるところ**: 難易度はビット数なので、時間比の **対数** で効く。
上限を入れないと何が起きるか（difficulty bomb / time warp）も実験してみるとよい。

---

## 課題 4 — タイムスタンプ検証

**なぜ**: `block.py` はタイムスタンプを一切検証していない。
偽の時刻を入れられると難易度調整を操作できる（time warp 攻撃）。
Bitcoin は 2 つの規則で挟んでいる。

- 直近 11 ブロックのタイムスタンプの **中央値** より後であること
- ネットワーク時刻 **+2 時間** より前であること

過去側に中央値を使うのは、マイナーが 1 つ嘘をついても効かないようにするため。

**実装するもの** — `chain/block.py`

```python
def timestamp_ok(candidate: int, recent: list[int], now: int,
                 future_limit: int = 2 * 60 * 60) -> bool:
    """recent（直近ブロックのタイムスタンプ）と now に照らして妥当か。"""
```

**要件**
- 直近 11 個の中央値以下なら `False`
- `now + future_limit` より後なら `False`
- その間なら `True`
- `recent` が空でも落ちない（genesis 直後）

---

## 課題 5 — SHA-256 を自作する

**なぜ**: このリポジトリで唯一 `hashlib` に頼っている部分。
圧縮関数を自分で書くと、**長さ拡張攻撃がなぜ起きるか**（そして
`dH`（2 段掛け）がなぜ要るか）が腑に落ちる。
Merkle–Damgård 構造では、`H(m)` を知っていれば `H(m || padding || x)` が
`m` を知らなくても計算できてしまう。内部状態がそのまま出力だからだ。

**実装するもの** — `chain/hashing.py`

```python
def sha256_from_scratch(data: bytes) -> bytes:
    """SHA-256 を自前で計算する（hashlib を使わない）。"""
```

**要件**
- `sha256_from_scratch(b"")`、`b"abc"`、長いメッセージのすべてで `hashlib` と一致
- 55 / 56 / 63 / 64 / 65 バイトで一致（パディング境界。ここでだいたい間違える）

**ヒント**: FIPS 180-4。8 個の初期ハッシュ値、64 個のラウンド定数、
メッセージスケジュール `w[16..63]`、そして 64 ラウンドの圧縮。
定数は「最初の 8 個 / 64 個の素数の平方根・立方根の小数部」から作れるので、
そこも自分で計算すると気持ちがいい。

---

## 課題 6 — Schnorr 署名

**なぜ**: ECDSA には延性があり、集約もできない。Schnorr は式が素直で
**線形性** を持つので、鍵と署名を足し合わせられる。
Bitcoin は 2021 年の Taproot でこちらへ移った。

    署名:  R = k*G,  e = H(R || P || m),  s = k + e*d
    検証:  s*G == R + e*P

なぜ通るか: `s*G = (k + e*d)*G = k*G + e*(d*G) = R + e*P`。1 行で終わる。
ECDSA の検証式と見比べると、逆元が消えているのが分かる。

**実装するもの** — `chain/schnorr.py`（新規ファイル）

```python
def sign(d: int, msg: bytes, k: int | None = None) -> tuple[Point, int]:
    """(R, s) を返す。"""

def verify(P: Point, msg: bytes, sig: tuple[Point, int]) -> bool:
    """s*G == R + e*P を確かめる。"""

def challenge(R: Point, P: Point, msg: bytes) -> int:
    """e = H(R || P || msg) mod N。"""
```

**要件**
- 正しい署名が通り、メッセージを変えると落ちる
- 別の鍵では通らない
- **線形性**: 鍵 `d1, d2` の署名を同じ `k` 由来でなく作った場合でも、
  `d = d1 + d2`、`P = P1 + P2` に対する署名が、個別の `s` の和で作れる
  （同じ `R` と同じ `e` を使う単純な集約。MuSig の入口）

**注意**: この単純な集約は、そのままでは **rogue key 攻撃** を受ける。
攻撃者が `P2 = Q - P1` を公開鍵として宣言すると、Alice の同意なしに
合成鍵 `Q` の署名を作れてしまう。MuSig はここを鍵ごとの係数で潰している。
実装したら、その攻撃も再現してみるとよい（これも 1 つの課題）。

**参考**: BIP 340 / MuSig2 論文

---

## 課題 7 以降

`docs/roadmap.md` にある。こちらはシグネチャを決めていない、もっと大きいもの。

- Phase 9 — スクリプト（スタックマシン、マルチシグ、タイムロック）
- Phase 10 — アカウントモデル（Ethereum 方向）
- eclipse 攻撃 / 疎なトポロジ
- Proof of Stake と finality
- チェーンの永続化、SSE、複数コンテナでの本当の P2P
