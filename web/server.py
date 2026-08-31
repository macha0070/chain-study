"""
chain-study lab — 観察用の Web サーバ

    python web/server.py            → http://localhost:8000
    PORT=9000 python web/server.py

方針
----
外部パッケージは使わない。`http.server` だけで組む。
Flask も FastAPI も使わないのは、リポジトリ全体の方針（標準ライブラリのみ）に
合わせるためと、HTTP サーバの中身もまた「読めば分かる大きさ」に保つため。

重い処理（採掘、遅延スイープ）はバックグラウンドスレッドで走らせ、
UI 側は `/api/state` を短い間隔で読みに来る。WebSocket も SSE も使わない。
状態が 1 つのオブジェクトに集約されているので、ポーリングで十分に足りる。
"""

from __future__ import annotations

import json
import os
import sys
import threading
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(ROOT, "..", "chain"))

import chain as chainmod                                          # noqa: E402
import curve                                                      # noqa: E402
import ecdsa                                                      # noqa: E402
import hashing                                                    # noqa: E402
import merkle                                                     # noqa: E402
import payment                                                    # noqa: E402
import scenario                                                   # noqa: E402
from node import Network                                          # noqa: E402
from tx import InvalidTx, Wallet, transfer                        # noqa: E402


STATIC = os.path.join(ROOT, "static")
DEFAULTS = {
    "nodes": 4,
    "difficulty": 14,
    "latency": 4.0,
    "interval": 30.0,
}


# ---------------------------------------------------------------- 実験台

class Lab:
    """ネットワーク 1 つと、UI から呼ばれる操作をまとめた実験台。

    すべての変更操作はロックの中で行う。バックグラウンドジョブが走っている
    最中に別の操作が入ると、ノードの状態が中途半端なまま観測されるため。
    """

    def __init__(self) -> None:
        self.lock = threading.RLock()
        self.job: dict | None = None
        self.notes: list[dict] = []
        self.reset(**DEFAULTS)

    # ------------------------------------------------------------ 構築

    def reset(self, nodes: int, difficulty: int, latency: float,
              interval: float, seed: int | None = None) -> None:
        with self.lock:
            self.config = {"nodes": int(nodes), "difficulty": int(difficulty),
                           "latency": float(latency), "interval": float(interval)}
            # ノードごとにハッシュ力を変える（現実のマイニングは均等ではない）
            rates = [0.40, 0.25, 0.20, 0.15] + [0.10] * 8
            self.net = Network(node_count=int(nodes), difficulty=int(difficulty),
                               latency=float(latency), block_interval=float(interval),
                               hashrates=rates[:int(nodes)], seed=seed)
            for name in ("Alice", "Bob", "Merchant"):
                self.net.wallet(name)
            # 店は自分のノードを持つ。他人の「入金しました」を信じないため。
            self.pos = payment.PaymentProcessor(self.net.nodes[0], "店舗")
            self.notes = []
            self.job = None
            self._note("reset", f"ノード {nodes} 台 / 難易度 {difficulty} / "
                                f"遅延 {latency}s / 間隔 {interval}s で初期化")

    def set_config(self, **kw) -> None:
        """走らせたまま遅延などを変える。チェーンは保持する。"""
        with self.lock:
            if "latency" in kw:
                self.net.latency = float(kw["latency"])
                self.config["latency"] = float(kw["latency"])
            if "interval" in kw:
                self.net.block_interval = float(kw["interval"])
                self.config["interval"] = float(kw["interval"])
            if "difficulty" in kw:
                d = int(kw["difficulty"])
                self.config["difficulty"] = d
                self.net.difficulty = d
                for n in self.net.nodes:
                    n.chain.difficulty = d
            self._note("config", f"設定を変更: {kw}")

    def _note(self, kind: str, text: str, **extra) -> None:
        self.notes.append({"t": round(self.net.now, 2) if hasattr(self, "net") else 0,
                           "kind": kind, "text": text, **extra})
        del self.notes[:-200]

    # ------------------------------------------------------------ ジョブ

    def start(self, label: str, fn) -> dict:
        """重い処理をバックグラウンドで走らせる。"""
        with self.lock:
            if self.job and self.job["running"]:
                return {"ok": False, "error": "実行中のジョブがあります"}
            self.job = {"label": label, "running": True, "done": 0,
                        "total": 0, "error": None}

        def runner():
            try:
                fn(self.job)
            except Exception as e:                              # noqa: BLE001
                self.job["error"] = f"{type(e).__name__}: {e}"
                traceback.print_exc()
            finally:
                self.job["running"] = False

        threading.Thread(target=runner, daemon=True).start()
        return {"ok": True}

    # ------------------------------------------------------------ 操作

    def mine(self, count: int) -> dict:
        def run(job):
            job["total"] = count
            for _ in range(count):
                with self.lock:
                    self.net.mine_next()
                    self.pos.poll(self.net.now)      # 注文の状態も進める
                job["done"] += 1
            with self.lock:
                self.net.settle()
                self.pos.poll(self.net.now)
        return self.start(f"{count} ブロック採掘", run)

    def settle(self) -> dict:
        with self.lock:
            self.net.settle()
            self._note("settle", "キュー内の全メッセージを配送し切った")
        return {"ok": True}

    def observer(self):
        return self.net.nodes[0]

    def faucet(self, wallet_name: str, amount: int) -> dict:
        """採掘報酬を持つノードから、指定ウォレットへ送金する。"""
        with self.lock:
            target = self.net.wallet(wallet_name)
            obs = self.observer()
            utxos = obs.chain.utxos
            donor = max(self.net.nodes,
                        key=lambda n: n.wallet.balance(utxos))
            if donor.wallet.balance(utxos) < amount:
                return {"ok": False,
                        "error": f"誰も {amount} を持っていない（先に採掘してください）"}
            t = transfer(donor.wallet, utxos, target.address, amount)
            self.net.submit_tx(t, origin=donor.id)
            self._note("faucet",
                       f"{donor.name} → {wallet_name} に {amount} を送金（未承認）")
            return {"ok": True, "txid": t.txid().hex()}

    def send(self, sender: str, to: str, amount: int, fee: int) -> dict:
        with self.lock:
            obs = self.observer()
            utxos = obs.chain.utxos
            src = self._find_wallet(sender)
            dst = self._find_wallet(to)
            if src is None or dst is None:
                return {"ok": False, "error": "ウォレットが見つかりません"}
            try:
                t = transfer(src, utxos, dst.address, int(amount), fee=int(fee))
            except InvalidTx as e:
                return {"ok": False, "error": str(e)}
            self.net.submit_tx(t, origin=0)
            self._note("tx", f"{sender} → {to} {amount}（手数料 {fee}）を投入")
            return {"ok": True, "txid": t.txid().hex()}

    def _find_wallet(self, name: str) -> Wallet | None:
        if name in self.net.wallets:
            return self.net.wallets[name]
        for n in self.net.nodes:
            if n.name == name:
                return n.wallet
        return None

    # ------------------------------------------------------------ 攻撃

    def attack_nonce_reuse(self) -> dict:
        """署名 2 本から秘密鍵を復元する（PS3 / Android ウォレット事件）。"""
        d = curve.gen_privkey()
        k = 0xC0FFEEBADC0DE1234567890
        z1 = ecdsa.msg_hash(b"Alice -> Bob : 10")
        z2 = ecdsa.msg_hash(b"Alice -> Carol : 3")
        s1 = ecdsa.sign(d, z1, k=k)
        s2 = ecdsa.sign(d, z2, k=k)
        recovered = ecdsa.recover_from_nonce_reuse(s1, z1, s2, z2)
        with self.lock:
            self._note("attack", "nonce 再利用による秘密鍵復元 → 成功")
        return {
            "ok": True, "kind": "nonce_reuse",
            "rows": [
                ("署名 1 の r", f"{s1.r:064x}"),
                ("署名 2 の r", f"{s2.r:064x}"),
                ("r の一致", str(s1.r == s2.r)),
                ("本物の秘密鍵", f"{d:064x}"),
                ("復元した秘密鍵", f"{recovered:064x}"),
                ("一致", str(recovered == d)),
            ],
            "verdict": "成功" if recovered == d else "失敗",
            "note": "計算したのは逆元 2 回だけ。曲線もハッシュも破っていない。"
                    "対策は RFC 6979（決定的 ECDSA）。",
        }

    def attack_merkle_cve(self) -> dict:
        """CVE-2012-2459: 中身の違う tx リストが同じマークル根を持つ。"""
        a, b, c = [hashing.dH(b"real-tx" + bytes([i])) for i in range(3)]
        r3 = merkle.merkle_root([a, b, c])
        r4 = merkle.merkle_root([a, b, c, c])
        with self.lock:
            self._note("attack", f"CVE-2012-2459 再現 → 根が一致: {r3 == r4}")
        return {
            "ok": True, "kind": "merkle_cve",
            "rows": [
                ("root([a,b,c])", r3.hex()),
                ("root([a,b,c,c])", r4.hex()),
                ("一致", str(r3 == r4)),
            ],
            "verdict": "成功" if r3 == r4 else "失敗",
            "note": "根が同じならブロックハッシュも同じ。攻撃者は正規ブロックを"
                    "膨らませて配り、受信ノードに正規ブロックごと invalid と"
                    "記録させられる。対策は重複段の拒否 / ドメイン分離ハッシュ。",
        }

    def attack_double_spend(self, amount: int = 40, confirmations: int = 3,
                            lead: int = 2) -> dict:
        """確認済みの支払いを、隠して掘った長い枝で消す（51% 攻撃）。

        手順そのものは `chain/scenario.py` にある。ここがやるのは
        「1 ステップごとにロックを取り直す」ことだけ。
        こうしておくと、攻撃の実行中も UI が状態を読み続けられる。
        """
        def run(job):
            job["total"] = confirmations + lead + 8      # 目安
            with self.lock:
                net = self.net
                gen = scenario.double_spend(
                    net, net.wallet("Alice"), net.wallet("Merchant"),
                    amount=amount, confirmations=confirmations, lead=lead)

            while True:
                with self.lock:
                    try:
                        step = next(gen)
                    except StopIteration as stop:
                        outcome = stop.value
                        break
                job["done"] += 1
                job["step"] = step

            with self.lock:
                self.job["result"] = {
                    "ok": True, "kind": "double_spend",
                    "rows": [
                        ("支払い額", str(outcome["amount"])),
                        ("待った確認数", str(outcome["confirmations"])),
                        ("隠し枝の長さ", str(outcome["hidden_blocks"])),
                        ("正直枝の仕事量", f"{outcome['honest_work']:,}"),
                        ("公開後の tip の仕事量", f"{outcome['attack_work']:,}"),
                        ("支払い tx はまだ有効か", str(outcome["payment_survived"])),
                        ("Merchant 残高（攻撃前）", str(outcome["merchant_before"])),
                        ("Merchant 残高（攻撃後）", str(outcome["merchant_after"])),
                    ],
                    "verdict": ("成功（支払いが消えた）" if outcome["succeeded"]
                                else "失敗（枝が足りない）"),
                    "note": "ブロックは 1 つも壊れていない。署名も PoW も全部有効なまま、"
                            "『どちらの枝を見るか』が変わっただけ。"
                            "暗号を破る必要はまったくない。",
                }

        return self.start("二重支払い攻撃", run)

    def latency_sweep(self) -> dict:
        """遅延と孤児率の関係を測る（Decker & Wattenhofer の再現）。"""
        ratios = [0.0, 0.02, 0.05, 0.10, 0.20, 0.35, 0.50, 0.75, 1.00]

        def run(job):
            job["total"] = len(ratios)
            rows = []
            for r in ratios:
                n = Network(node_count=6, difficulty=10, latency=30.0 * r,
                            block_interval=30.0, seed=1234)
                n.run(60)
                n.settle()
                s = n.stats()
                rows.append({"ratio": r, "latency": round(30.0 * r, 1),
                             "orphans": s["orphans"], "total": s["total_blocks"],
                             "rate": round(s["orphan_rate"], 4)})
                job["done"] += 1
                job["rows"] = rows
            self.job["result"] = {
                "ok": True, "kind": "latency_sweep", "chart": rows,
                "verdict": f"孤児率 {rows[0]['rate']:.1%} → {rows[-1]['rate']:.1%}",
                "note": "孤児率は およそ『伝播遅延 / ブロック間隔』に比例して増える。"
                        "孤児になった仕事はセキュリティに寄与しない。"
                        "Bitcoin がブロック間隔を 10 分に置いている理由。",
            }
            with self.lock:
                self._note("attack", "遅延スイープ完了")

        return self.start("遅延スイープ", run)

    # ------------------------------------------------------------ 決済（POS）

    def pos_state(self) -> dict:
        """レジ画面の状態。呼ぶたびにチェーンを見直して注文を更新する。"""
        with self.lock:
            self.pos.poll(self.net.now)
            obs = self.observer()
            utxos = obs.chain.utxos
            invoices = [inv.view() for inv in self.pos.invoices.values()]
            invoices.sort(key=lambda i: -i["id"])
            return {
                "now": round(self.net.now, 2),
                "height": obs.chain.height() if obs.chain.tip else -1,
                "invoices": invoices,
                "released": sorted(self.pos.released),
                "summary": self.pos.summary(),
                "log": self.pos.log[-40:],
                "customers": [
                    {"name": w.name, "balance": w.balance(utxos)}
                    for w in self.net.wallets.values()
                ],
                "policy_table": [
                    {"amount": a, "required": z, "loss": round(loss, 4)}
                    for a, z, loss in payment.confirmation_table(
                        [1, 10, 50, 100, 500, 1000, 10000])
                ],
                "job": self.job,
            }

    def pos_create(self, amount: int, memo: str, attacker_share: float,
                   tolerated_loss: float) -> dict:
        with self.lock:
            inv = self.pos.create_invoice(
                amount=int(amount), memo=memo or "", now=self.net.now,
                attacker_share=float(attacker_share),
                tolerated_loss=float(tolerated_loss))
            self._note("invoice", f"請求書 #{inv.id} {inv.amount} を発行")
            return {"ok": True, "invoice": inv.view()}

    def pos_pay(self, invoice_id: int, payer: str, amount: int | None) -> dict:
        with self.lock:
            inv = self.pos.invoices.get(int(invoice_id))
            if inv is None:
                return {"ok": False, "error": "その請求書はありません"}
            wallet = self._find_wallet(payer)
            if wallet is None:
                return {"ok": False, "error": "ウォレットが見つかりません"}
            try:
                t = payment.pay_invoice(wallet, self.observer(), inv, self.net,
                                        amount=amount)
            except InvalidTx as e:
                return {"ok": False, "error": str(e)}
            self.pos.poll(self.net.now)
            self._note("tx", f"{payer} が請求書 #{inv.id} に支払った")
            return {"ok": True, "txid": t.txid().hex()}

    def pos_release(self, invoice_id: int, force: bool) -> dict:
        with self.lock:
            self.pos.poll(self.net.now)
            if int(invoice_id) not in self.pos.invoices:
                return {"ok": False, "error": "その請求書はありません"}
            ok, msg = self.pos.release(int(invoice_id), self.net.now, force=force)
            return {"ok": ok, "message": msg}

    def pos_attack(self, invoice_id: int, release_at: int = 1,
                   lead: int = 2) -> dict:
        """この請求書を狙って二重支払いする。

        店が release_at 確認で商品を渡してしまう設定にしておき、
        そのあと攻撃者が隠し枝を公開する。
        「待つ長さを縮めると何が起きるか」をそのまま実演する。
        """
        def run(job):
            job["total"] = release_at + lead + 8
            with self.lock:
                inv = self.pos.invoices[int(invoice_id)]
                gen = scenario.double_spend(
                    self.net, self.net.wallet("Alice"), inv.wallet,
                    amount=inv.amount, confirmations=release_at, lead=lead)

            while True:
                with self.lock:
                    try:
                        step = next(gen)
                    except StopIteration as stop:
                        outcome = stop.value
                        break
                    # 1 ステップごとに店の判断も進める
                    self.pos.poll(self.net.now)
                    if (inv.confirmations >= release_at
                            and inv.id not in self.pos.released
                            and inv.status in (payment.CONFIRMING, payment.SETTLED)):
                        self.pos.release(inv.id, self.net.now, force=True)
                job["done"] += 1
                job["step"] = step

            with self.lock:
                self.pos.poll(self.net.now)
                view = inv.view()
                lost = inv.id in self.pos.released and inv.status == payment.REVERSED
                self.job["result"] = {
                    "ok": True, "kind": "pos_double_spend",
                    "rows": [
                        ("請求書", f"#{inv.id}  {inv.amount}"),
                        ("ポリシー上の必要確認数", str(inv.required)),
                        ("店が渡した時点の確認数", str(release_at)),
                        ("渡した時点の期待損失",
                         f"{chainmod.attacker_success_probability(inv.attacker_share, release_at) * inv.amount:.2f}"),
                        ("攻撃者の隠し枝", f"{outcome['hidden_blocks']} ブロック"),
                        ("最終的な注文の状態", view["status"]),
                        ("商品を渡したか", "はい" if inv.id in self.pos.released else "いいえ"),
                        ("損失", str(inv.amount if lost else 0)),
                    ],
                    "verdict": ("成功（商品を渡したあとで支払いが消えた）" if lost
                                else "失敗（注文は巻き戻らなかった）"),
                    "note": "チェーンも署名も壊れていない。壊れたのは"
                            "『何確認で渡すか』という店の判断のほう。",
                }

        return self.start(f"請求書 #{invoice_id} を狙った二重支払い", run)

    def confirmations_table(self) -> dict:
        """中本論文 11 節の式で、確認数ごとの逆転確率を出す。"""
        qs = [0.05, 0.10, 0.25, 0.35, 0.45]
        zs = [0, 1, 2, 3, 4, 6, 8, 12, 24]
        return {
            "ok": True, "kind": "confirmations",
            "qs": qs, "zs": zs,
            "grid": [[chainmod.attacker_success_probability(q, z) for q in qs]
                     for z in zs],
            "note": "z=0 ではどんな弱い攻撃者でも成功率 100%。q が 50% を超えると"
                    "確認をいくら重ねても 1 になる。これが 51% 攻撃。",
        }

    # ------------------------------------------------------------ 状態

    def snapshot(self) -> dict:
        with self.lock:
            net = self.net
            obs = self.observer()
            canonical = net.canonical_hashes(0)
            all_blocks = net.all_blocks()
            tips = {n.chain.tip: [] for n in net.nodes}
            for n in net.nodes:
                tips.setdefault(n.chain.tip, []).append(n.id)

            lanes = self._layout(all_blocks, obs)
            blocks = []
            for h, blk in all_blocks.items():
                blocks.append({
                    "hash": h.hex(),
                    "short": h[:6].hex(),
                    "prev": blk.header.prev_hash.hex(),
                    "height": obs.chain.height(h) if h in obs.chain.blocks
                              else self._height_via(all_blocks, h),
                    "lane": lanes.get(h, 0),
                    "canonical": h in canonical,
                    "txs": len(blk.txs),
                    "difficulty": blk.header.difficulty,
                    "nonce": blk.header.nonce,
                    "merkle_root": blk.header.merkle_root.hex(),
                    "tip_of": tips.get(h, []),
                    "leading_zeros": hashing.leading_zero_bits(h),
                })
            blocks.sort(key=lambda b: (b["height"], b["lane"]))

            utxos = obs.chain.utxos
            wallets = [{"name": w.name, "address": w.address.hex()[:12],
                        "balance": w.balance(utxos), "kind": "user"}
                       for w in net.wallets.values()]
            wallets += [{"name": n.name, "address": n.wallet.address.hex()[:12],
                         "balance": n.wallet.balance(utxos), "kind": "miner"}
                        for n in net.nodes]

            log = sorted(net.log + self.notes, key=lambda e: e["t"])[-60:]

            return {
                "config": self.config,
                "stats": net.stats(0),
                "nodes": [n.view() for n in net.nodes],
                "blocks": blocks,
                "wallets": wallets,
                "log": log,
                "job": self.job,
                "utxo_count": len(utxos),
            }

    def _height_via(self, all_blocks, h: bytes) -> int:
        """観測者が知らないブロックの高さを、全体ビューから求める。"""
        n = 0
        while h in all_blocks:
            h = all_blocks[h].header.prev_hash
            n += 1
        return n - 1

    def _layout(self, all_blocks, obs) -> dict[bytes, int]:
        """描画用のレーン割り当て。正典チェーンを lane 0 に置く。"""
        lanes: dict[bytes, int] = {}
        for blk in obs.chain.branch():
            lanes[blk.hash()] = 0

        # 深い方から処理する。枝の先端から根元まで一気に辿ることで、
        # 1 本の枝が 1 レーンに収まる（浅い順だとブロックごとに
        # レーンが増えて、枝が階段状に見えてしまう）。
        remaining = [h for h in all_blocks if h not in lanes]
        remaining.sort(key=lambda h: -self._height_via(all_blocks, h))
        next_lane = 1
        for h in remaining:
            if h in lanes:
                continue
            # この枝を根元まで辿り、まとめて 1 レーンに置く
            segment, cur = [], h
            while cur in all_blocks and cur not in lanes:
                segment.append(cur)
                cur = all_blocks[cur].header.prev_hash
            for s in segment:
                lanes[s] = next_lane
            next_lane += 1
        return lanes

    def block_detail(self, hash_hex: str) -> dict:
        with self.lock:
            all_blocks = self.net.all_blocks()
            h = bytes.fromhex(hash_hex)
            blk = all_blocks.get(h)
            if blk is None:
                return {"ok": False, "error": "unknown block"}
            obs = self.observer()
            txs = []
            for t in blk.txs:
                txs.append({
                    "txid": t.txid().hex(),
                    "coinbase": t.is_coinbase(),
                    "inputs": [str(i.prev) for i in t.inputs],
                    "outputs": [{"amount": o.amount,
                                 "address": o.address.hex()[:12]}
                                for o in t.outputs],
                })
            return {
                "ok": True,
                "hash": h.hex(),
                "prev": blk.header.prev_hash.hex(),
                "merkle_root": blk.header.merkle_root.hex(),
                "timestamp": blk.header.timestamp,
                "difficulty": blk.header.difficulty,
                "nonce": blk.header.nonce,
                "leading_zeros": hashing.leading_zero_bits(h),
                "canonical": h in self.net.canonical_hashes(0),
                "height": obs.chain.height(h) if h in obs.chain.blocks
                          else self._height_via(all_blocks, h),
                "txs": txs,
            }


LAB = Lab()


# ---------------------------------------------------------------- HTTP

class Handler(BaseHTTPRequestHandler):
    server_version = "chain-study/1.0"

    def log_message(self, fmt, *args):                          # 静かにする
        if os.environ.get("CHAIN_STUDY_VERBOSE"):
            super().log_message(fmt, *args)

    # -------------------------------------------------------- 応答補助

    def _json(self, obj, status: int = 200) -> None:
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _file(self, path: str) -> None:
        full = os.path.normpath(os.path.join(STATIC, path.lstrip("/")))
        if not full.startswith(STATIC) or not os.path.isfile(full):
            self.send_error(404)
            return
        ctype = {".html": "text/html; charset=utf-8",
                 ".js": "text/javascript; charset=utf-8",
                 ".css": "text/css; charset=utf-8"}.get(
                     os.path.splitext(full)[1], "application/octet-stream")
        with open(full, "rb") as f:
            body = f.read()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _body(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        if not length:
            return {}
        try:
            return json.loads(self.rfile.read(length).decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return {}

    # -------------------------------------------------------- ルーティング

    def do_GET(self) -> None:                                   # noqa: N802
        url = urlparse(self.path)
        p, q = url.path, parse_qs(url.query)
        try:
            if p == "/":
                self._file("index.html")
            elif p in ("/pos", "/pos/"):
                self._file("pos.html")
            elif p.startswith("/static/"):
                self._file(p[len("/static/"):])
            elif p == "/api/state":
                self._json(LAB.snapshot())
            elif p == "/api/pos/state":
                self._json(LAB.pos_state())
            elif p == "/api/block":
                self._json(LAB.block_detail(q.get("hash", [""])[0]))
            elif p == "/api/confirmations":
                self._json(LAB.confirmations_table())
            elif p == "/api/health":
                self._json({"ok": True})
            else:
                self.send_error(404)
        except Exception as e:                                  # noqa: BLE001
            traceback.print_exc()
            self._json({"ok": False, "error": f"{type(e).__name__}: {e}"}, 500)

    def do_POST(self) -> None:                                  # noqa: N802
        p = urlparse(self.path).path
        body = self._body()
        try:
            if p == "/api/reset":
                LAB.reset(nodes=body.get("nodes", DEFAULTS["nodes"]),
                          difficulty=body.get("difficulty", DEFAULTS["difficulty"]),
                          latency=body.get("latency", DEFAULTS["latency"]),
                          interval=body.get("interval", DEFAULTS["interval"]))
                self._json({"ok": True})
            elif p == "/api/config":
                LAB.set_config(**body)
                self._json({"ok": True})
            elif p == "/api/mine":
                self._json(LAB.mine(int(body.get("count", 1))))
            elif p == "/api/settle":
                self._json(LAB.settle())
            elif p == "/api/faucet":
                self._json(LAB.faucet(body.get("wallet", "Alice"),
                                      int(body.get("amount", 50))))
            elif p == "/api/send":
                self._json(LAB.send(body.get("from", "Alice"),
                                    body.get("to", "Bob"),
                                    body.get("amount", 10),
                                    body.get("fee", 1)))
            elif p == "/api/attack/nonce_reuse":
                self._json(LAB.attack_nonce_reuse())
            elif p == "/api/attack/merkle_cve":
                self._json(LAB.attack_merkle_cve())
            elif p == "/api/attack/double_spend":
                self._json(LAB.attack_double_spend(
                    amount=int(body.get("amount", 40)),
                    confirmations=int(body.get("confirmations", 3)),
                    lead=int(body.get("lead", 2))))
            elif p == "/api/attack/latency_sweep":
                self._json(LAB.latency_sweep())
            elif p == "/api/pos/invoice":
                self._json(LAB.pos_create(
                    amount=body.get("amount", 10),
                    memo=body.get("memo", ""),
                    attacker_share=body.get("attacker_share", 0.10),
                    tolerated_loss=body.get("tolerated_loss", 0.5)))
            elif p == "/api/pos/pay":
                self._json(LAB.pos_pay(body.get("invoice_id"),
                                       body.get("from", "Alice"),
                                       body.get("amount")))
            elif p == "/api/pos/release":
                self._json(LAB.pos_release(body.get("invoice_id"),
                                           bool(body.get("force", False))))
            elif p == "/api/pos/attack":
                self._json(LAB.pos_attack(body.get("invoice_id"),
                                          int(body.get("release_at", 1)),
                                          int(body.get("lead", 2))))
            else:
                self.send_error(404)
        except InvalidTx as e:
            self._json({"ok": False, "error": str(e)}, 400)
        except Exception as e:                                  # noqa: BLE001
            traceback.print_exc()
            self._json({"ok": False, "error": f"{type(e).__name__}: {e}"}, 500)


def main() -> None:
    port = int(os.environ.get("PORT", "8000"))
    host = os.environ.get("HOST", "0.0.0.0")
    srv = ThreadingHTTPServer((host, port), Handler)
    shown = "localhost" if host in ("0.0.0.0", "") else host
    print(f"chain-study lab → http://{shown}:{port}")
    print("  Ctrl-C で停止")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n停止しました")


if __name__ == "__main__":
    main()
