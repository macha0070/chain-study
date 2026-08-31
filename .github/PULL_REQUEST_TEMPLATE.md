## 何を変えたか

<!-- 1〜2 文で -->

## どのフェーズ / 課題か

<!-- 例) EXERCISES.md 課題 3（難易度の自動調整） -->

## 確認したこと

- [ ] `python chain/demo.py --check` が通る
- [ ] `python -m unittest discover -s tests` が通る
- [ ] 追加パッケージを増やしていない（標準ライブラリのみ）
- [ ] 教材として読める（なぜそれが要るのかが docstring に書いてある）

## 攻撃の再現に影響するか

<!--
このリポジトリは「攻撃が成功すること」自体をテストで守っています。
tests/test_chain.py の test_nonce_reuse_leaks_private_key /
test_cve_2012_2459_is_reproducible / test_reorg_undoes_a_confirmed_payment
を意図的に変えた場合は、その理由を書いてください。
-->
