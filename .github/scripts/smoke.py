"""
CI 用スモークテスト — 起動中のコンテナに API 越しで話しかける。

確認すること:
  1. チェーンが伸びる
  2. README に書いた 3 つの攻撃が、実際に成功する

3 番目が大事。教材の主張（「この攻撃は成功する」）が壊れたら CI を赤くしたい。
ドキュメントとコードがずれる典型的な腐り方を、ここで止める。
"""

from __future__ import annotations

import json
import sys
import time
import urllib.error
import urllib.request

BASE = "http://127.0.0.1:8000"
FAILURES: list[str] = []

# Windows で出力をパイプすると locale (cp932) が使われて日本語が壊れる。
# CI は Linux なので問題ないが、CONTRIBUTING.md は手元で実行するよう言っている。
for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(encoding="utf-8", errors="replace")


def post(path: str, body: dict | None = None) -> dict:
    req = urllib.request.Request(
        BASE + path, method="POST",
        data=json.dumps(body or {}).encode(),
        headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)


def get(path: str) -> dict:
    with urllib.request.urlopen(BASE + path, timeout=30) as r:
        return json.load(r)


def wait_for_job(timeout: float = 180.0) -> dict:
    deadline = time.time() + timeout
    while time.time() < deadline:
        state = get("/api/state")
        job = state.get("job")
        if not job or not job.get("running"):
            return state
        time.sleep(0.4)
    raise TimeoutError("ジョブが終わりませんでした")


def _find_order(invoice_id: int) -> dict:
    for inv in get("/api/pos/state")["invoices"]:
        if inv["id"] == invoice_id:
            return inv
    raise KeyError(f"請求書 #{invoice_id} が見つかりません")


def check(label: str, ok: bool, detail: str = "") -> None:
    mark = "ok  " if ok else "FAIL"
    print(f"  [{mark}] {label}{'  ' + detail if detail else ''}")
    if not ok:
        FAILURES.append(label)


def main() -> int:
    print("1. チェーンを伸ばす")
    post("/api/reset", {"nodes": 4, "difficulty": 12, "latency": 6, "interval": 30})
    post("/api/mine", {"count": 12})
    state = wait_for_job()
    stats = state["stats"]
    height = state["nodes"][0]["height"]

    # 採掘数 = 正典の高さ、ではない。遅延があると一部が孤児になるので
    # 「正典 + 孤児 = 全ブロック」が成り立つほうを見る。
    # ここを height >= 12 で書くと、孤児が出た瞬間に嘘の失敗になる。
    check("genesis + 12 ブロックが存在する", stats["total_blocks"] == 13,
          f"{stats['total_blocks']} 個")
    check("正典 + 孤児 = 全ブロック",
          stats["canonical"] + stats["orphans"] == stats["total_blocks"],
          f"{stats['canonical']} + {stats['orphans']} = {stats['total_blocks']}")
    check("正典の高さと本数が合っている", stats["canonical"] == height + 1,
          f"高さ {height} / 正典 {stats['canonical']} 本")
    check("全ノードが合意している", stats["converged"])

    print("\n2. nonce 再利用で秘密鍵が復元できる")
    r = post("/api/attack/nonce_reuse")
    check("秘密鍵を復元した", r["verdict"] == "成功", r["verdict"])

    print("\n3. CVE-2012-2459 が再現する")
    r = post("/api/attack/merkle_cve")
    check("違う tx リストが同じ根を持った", r["verdict"] == "成功", r["verdict"])

    print("\n4. リオーグで確認済みの支払いが消える")
    before = get("/api/state")
    post("/api/attack/double_spend",
         {"amount": 40, "confirmations": 3, "lead": 2})
    state = wait_for_job()
    job = state["job"]
    if job.get("error"):
        check("攻撃が完走した", False, job["error"])
    else:
        result = job.get("result") or {}
        rows = dict(result.get("rows", []))
        check("攻撃が成功した", result.get("verdict", "").startswith("成功"),
              result.get("verdict", "?"))
        check("支払い tx が正典チェーンから消えた",
              rows.get("支払い tx はまだ有効か") == "False")
        check("Merchant の残高が 0 になった",
              rows.get("Merchant 残高（攻撃後）") == "0",
              f"{rows.get('Merchant 残高（攻撃前）')} -> {rows.get('Merchant 残高（攻撃後）')}")
        check("孤児ブロックが生まれた",
              state["stats"]["orphans"] > before["stats"]["orphans"],
              f"{state['stats']['orphans']} 個")

    print("\n5. 決済アプリ — 0 確認では渡せず、待てば確定する")
    post("/api/reset", {"nodes": 4, "difficulty": 12, "latency": 4, "interval": 30})
    post("/api/mine", {"count": 10})
    wait_for_job()
    faucet = post("/api/faucet", {"wallet": "Alice", "amount": 100})
    check("Alice に元手を配れた", faucet.get("ok", False), faucet.get("error", ""))
    post("/api/mine", {"count": 2})
    wait_for_job()

    created = post("/api/pos/invoice", {"amount": 40, "memo": "CI テスト"})
    invoice_id = created["invoice"]["id"]
    required = created["invoice"]["required"]
    check("請求書が 1 確認以上を要求する", required >= 1, f"{required} 確認")

    paid = post("/api/pos/pay", {"invoice_id": invoice_id, "from": "Alice"})
    check("支払いを投入できた", paid.get("ok", False), paid.get("error", ""))

    order = _find_order(invoice_id)
    check("0 確認では safe にならない",
          order["status"] == "detected" and not order["safe"],
          f"{order['status']} / safe={order['safe']}")
    check("0 確認の期待損失は全額",
          abs(order["expected_loss"] - order["amount"]) < 1e-6,
          f"{order['expected_loss']}")

    denied = post("/api/pos/release", {"invoice_id": invoice_id})
    check("0 確認での引き渡しは拒否される", not denied.get("ok", True),
          denied.get("message", ""))

    losses = []
    for _ in range(required + 4):
        post("/api/mine", {"count": 1})
        wait_for_job()
        order = _find_order(invoice_id)
        losses.append(order["expected_loss"])
        if order["safe"]:
            break
    check("待てば settled になる", order["status"] == "settled",
          f"{order['status']} / {order['confirmations']}確認")
    check("期待損失は単調に下がる", losses == sorted(losses, reverse=True),
          " → ".join(f"{v:.2f}" for v in losses))
    released = post("/api/pos/release", {"invoice_id": invoice_id})
    check("settled なら引き渡せる", released.get("ok", False),
          released.get("message", ""))

    print("\n6. 待たずに渡すと、実際に商品を失う")
    inv2 = post("/api/pos/invoice", {"amount": 60, "memo": "CI 攻撃対象"})
    id2 = inv2["invoice"]["id"]
    post("/api/pos/attack", {"invoice_id": id2, "release_at": 1, "lead": 2})
    state = wait_for_job()
    if state["job"].get("error"):
        check("攻撃が完走した", False, state["job"]["error"])
    else:
        order2 = _find_order(id2)
        summary = get("/api/pos/state")["summary"]
        check("1 確認で渡した注文が巻き戻った", order2["status"] == "reversed",
              order2["status"])
        check("損失が記録されている", summary["reversed_after_release"] >= 1,
              f"損失 {summary['lost_amount']}")

    print()
    if FAILURES:
        print(f"失敗 {len(FAILURES)} 件: {', '.join(FAILURES)}")
        return 1
    print("すべて通過。教材の主張はコードと一致しています。")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (urllib.error.URLError, TimeoutError) as e:
        print(f"サーバに到達できませんでした: {e}")
        sys.exit(1)
