# 手を入れるときの約束

学習リポジトリなので、「速い」「短い」より **読んで分かる** を優先する。
以下は好みの問題ではなく、この教材が成り立つための前提。

## 1. 依存を増やさない

標準ライブラリだけで書く。`requirements.txt` も `pyproject.toml` も置かない。
CI がその存在を検査して落とす。

なぜか: `pip install ecdsa` した瞬間に、このリポジトリの意味の半分が消える。
楕円曲線を自分で書いたから secp256k1 が分かるのであって、
呼び出しただけでは分からない。`hashlib` だけは例外にしてあるが、
それも課題 5 で自作する対象として残してある。

## 2. なぜそれが在るのかを書く

各モジュールの docstring は **「なぜ必要か」「方針メモ」「到達点」** の 3 つで始める。
関数の docstring には、式そのものより **なぜその式で正しいのか** を書く。

良い例（`chain/ecdsa.py`）:

```
なぜ通るか（この 2 行が全部）:
    u1*G + u2*Q = (z/s)*G + (r/s)*(d*G) = ((z + r*d)/s)*G = k*G = R
    最後の等号は s = k^{-1}(z + r*d) を s で解いた (z + r*d)/s = k から。
```

## 3. 到達判定を置く

「実装した」ではなく「**何が出力されたら理解できたと言えるか**」を先に決める。
新しいフェーズを足すなら、`self_check()`（教材としての到達判定）と
`demo()`（観察ポイントの出力）を対にする。

`demo()` の最後は `→` で始まる考察で締める。数字を出しただけでは教材にならない。

## 4. 攻撃は塞がない

`ecdsa.recover_from_nonce_reuse()`、`merkle.merkle_root()` の奇数複製、
リオーグによる二重支払い — これらは **わざと直していない**。
先に対策を書くと、なぜそれが要るのか分からないまま通り過ぎてしまう。

対策は `EXERCISES.md` の課題として、別の関数名で足す
（例: `merkle_root` は残したまま `safe_merkle_root` を追加する）。

この方針を守るために、**攻撃が成功し続けること自体がテストになっている**。

- `test_nonce_reuse_leaks_private_key`
- `test_cve_2012_2459_is_reproducible`
- `test_reorg_undoes_a_confirmed_payment`

これらを赤くする変更は、意図的でない限り受け入れられない。

## 5. 模擬と実物を混ぜない

`chain/node.py` の PoW は本物（実際に nonce を探す）だが、
「次に誰がいつ当てるか」は指数分布からの抽選で模擬している。
こういう割り切りは **必ず冒頭に明記する**。

結果の読み方を間違えさせないため。教材が嘘をつくのがいちばん悪い。

## 6. 層の向きを守る

```
hashing → curve → ecdsa → merkle → tx → block → chain → node → scenario
```

依存は一方向。`web/` は `chain/` を呼ぶが、`chain/` は `web/` を知らない。
攻撃シナリオを `web/server.py` ではなく `chain/scenario.py` に置いてあるのは、
CLI からも図の生成からもテストからも同じものを使うため。

## 7. 送る前に

```bash
python chain/demo.py --check
python -m unittest discover -s tests
python tools/render_svg.py        # 図に影響する変更をしたなら
```

Docker まで見るなら:

```bash
docker compose run --rm tests
docker compose up -d && python .github/scripts/smoke.py
```

## 質問は歓迎

「分からない」は教材側の不足。Issue の
[分からないところがある](../../issues/new?template=question.yml) からどうぞ。
どこで詰まったかが分かると、その部分の説明を書き直せる。
