"""
README 用の図を、実際にチェーンを動かして生成する

    python tools/render_svg.py              docs/img/ に書き出す
    python tools/render_svg.py --out /tmp   出力先を変える

なぜ手描きの図にしないか
------------------------
図と実装がずれるから。ここで出す図はすべて、その場でチェーンを走らせた
実測値から描いている。孤児率の棒グラフは本当に測った孤児率だし、
リオーグの図は本当にリオーグしたチェーンの形。

出力は素の SVG（shape と text だけ）。GitHub の Markdown は SVG を
サニタイズするので、script も foreignObject も使わない。
背景を自前で塗るので、GitHub の light / dark どちらでも読める。
"""

from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "chain"))

import scenario                                                   # noqa: E402
from chain import attacker_success_probability                    # noqa: E402
from node import Network                                          # noqa: E402
from util import enable_utf8_stdout                               # noqa: E402


# 図の配色。UI と揃えてある。
BG = "#0f1420"
PANEL = "#182033"
LINE = "#2a3550"
TEXT = "#e7edf7"
DIM = "#8794ab"
CANON = "#56d39a"
CANON_FILL = "#17352a"
ORPHAN = "#ff6b6b"
ORPHAN_FILL = "#2b1a1f"
WARN = "#f0b64e"
MONO = "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace"
SANS = "system-ui, -apple-system, 'Segoe UI', sans-serif"


def esc(s: str) -> str:
    return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


def text(x, y, s, *, fill=TEXT, size=12, family=SANS, anchor="start", weight="normal"):
    return (f'<text x="{x}" y="{y}" fill="{fill}" font-size="{size}" '
            f'font-family="{family}" text-anchor="{anchor}" '
            f'font-weight="{weight}">{esc(str(s))}</text>')


def frame(width: int, height: int, body: str, title: str, subtitle: str = "") -> str:
    head = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}" role="img" aria-label="{esc(title)}">',
        f'<rect width="{width}" height="{height}" rx="12" fill="{BG}"/>',
        text(22, 30, title, size=15, weight="600"),
    ]
    if subtitle:
        head.append(text(22, 50, subtitle, fill=DIM, size=11.5))
    return "\n".join(head) + "\n" + body + "\n</svg>\n"


# ---------------------------------------------------------------- 図 1: リオーグ

def figure_reorg(path: str) -> None:
    """二重支払い攻撃を実行し、その結果できたチェーンの形を描く。"""
    net = Network(node_count=4, difficulty=12, latency=3.0,
                  block_interval=30.0, seed=31337)
    net.run(3)
    net.settle()
    alice, merchant = net.wallet("Alice"), net.wallet("Merchant")
    result = scenario.run(scenario.double_spend(
        net, alice, merchant, amount=40, confirmations=3, lead=2))

    obs = net.nodes[0]
    all_blocks = net.all_blocks()
    canonical = net.canonical_hashes(0)

    def height_of(h: bytes) -> int:
        n = 0
        while h in all_blocks:
            h = all_blocks[h].header.prev_hash
            n += 1
        return n - 1

    # レーン: 正典を 0、そこから外れた枝を先端から辿って 1 本ずつ
    lanes: dict[bytes, int] = {b.hash(): 0 for b in obs.chain.branch()}
    rest = sorted((h for h in all_blocks if h not in lanes),
                  key=lambda h: -height_of(h))
    lane = 1
    for h in rest:
        if h in lanes:
            continue
        seg, cur = [], h
        while cur in all_blocks and cur not in lanes:
            seg.append(cur)
            cur = all_blocks[cur].header.prev_hash
        for x in seg:
            lanes[x] = lane
        lane += 1

    # 支払い tx が入っていたブロック（= 捨てられた枝の中）を目立たせる
    pay_txid = bytes.fromhex(result["payment_txid"])
    pay_block = next((h for h, b in all_blocks.items()
                      if any(t.txid() == pay_txid for t in b.txs)), None)

    # 分岐点の手前 2 ブロックから右だけを描く。
    # チェーン全部を出すと横に長いばかりで、肝心の枝分かれが小さくなる。
    fork_h = height_of(bytes.fromhex(result["fork_point"]))
    window_lo = max(0, fork_h - 2)
    shown = {h: b for h, b in all_blocks.items() if height_of(h) >= window_lo}
    truncated = len(shown) < len(all_blocks)

    W, H, BW, BH = 96, 76, 74, 46
    PAD_X, TOP = 22 + (26 if truncated else 0), 78
    heights = [height_of(h) for h in shown]
    lo, hi = min(heights), max(heights)
    width = PAD_X + (hi - lo + 1) * W + 22
    height = TOP + (max(lanes[h] for h in shown) + 1) * H + 62

    pos = {h: (PAD_X + (height_of(h) - lo) * W, TOP + lanes[h] * H)
           for h in shown}

    parts = []
    if truncated:
        # 左に続きがあることを示す
        parts.append(text(18, TOP + BH / 2 + 4, "…", fill=DIM, size=20))
        parts.append(f'<path d="M30,{TOP + BH / 2} L{PAD_X},{TOP + BH / 2}" '
                     f'stroke="{CANON}" stroke-opacity="0.45" stroke-width="2"/>')

    for h, blk in shown.items():
        prev = blk.header.prev_hash
        if prev not in pos:
            continue
        x1, y1 = pos[prev][0] + BW, pos[prev][1] + BH / 2
        x2, y2 = pos[h][0], pos[h][1] + BH / 2
        mx = (x1 + x2) / 2
        stroke = CANON if h in canonical else ORPHAN
        parts.append(f'<path d="M{x1},{y1} C{mx},{y1} {mx},{y2} {x2},{y2}" '
                     f'fill="none" stroke="{stroke}" stroke-opacity="0.45" '
                     f'stroke-width="2"/>')

    for h, blk in shown.items():
        x, y = pos[h]
        canon = h in canonical
        fill = CANON_FILL if canon else ORPHAN_FILL
        edge = CANON if canon else ORPHAN
        sw = 2.5 if h == pay_block else 1.4
        parts.append(f'<rect x="{x}" y="{y}" width="{BW}" height="{BH}" rx="8" '
                     f'fill="{fill}" stroke="{edge}" stroke-width="{sw}"/>')
        parts.append(text(x + BW / 2, y + 19, h[:4].hex(),
                          fill=CANON if canon else ORPHAN, size=11,
                          family=MONO, anchor="middle"))
        parts.append(text(x + BW / 2, y + 34, f"#{height_of(h)} · {len(blk.txs)}tx",
                          fill=DIM, size=10, family=MONO, anchor="middle"))

    if pay_block is not None and pay_block in pos:
        px, py = pos[pay_block]
        parts.append(text(px + BW / 2, py + BH + 17, "支払い tx はこの中",
                          fill=WARN, size=11, anchor="middle"))
        parts.append(text(px + BW / 2, py + BH + 31, "（捨てられた枝）",
                          fill=WARN, size=10, anchor="middle"))

    tip = obs.chain.tip
    tx, ty = pos[tip]
    parts.append(text(tx + BW / 2, ty - 9, "tip", fill=CANON, size=11,
                      anchor="middle", weight="600"))

    legend_y = height - 20
    parts.append(f'<rect x="22" y="{legend_y - 11}" width="11" height="11" rx="3" '
                 f'fill="{CANON_FILL}" stroke="{CANON}"/>')
    parts.append(text(40, legend_y - 1, "正典チェーン（全ノードが選んだ枝）",
                      fill=DIM, size=11))
    parts.append(f'<rect x="270" y="{legend_y - 11}" width="11" height="11" rx="3" '
                 f'fill="{ORPHAN_FILL}" stroke="{ORPHAN}"/>')
    parts.append(text(288, legend_y - 1,
                      "孤児（有効なのに選ばれなかった枝）", fill=DIM, size=11))

    subtitle = (f"{result['confirmations']} 確認まで待った {result['amount']} の支払いが、"
                f"隠して掘った {result['hidden_blocks']} ブロックの枝で消えた"
                f"　商店の残高 {result['merchant_before']} → {result['merchant_after']}")
    svg = frame(width, height, "\n".join(parts),
                "51% 攻撃 — 確認済みの支払いが消える", subtitle)
    _write(path, svg)
    return result


# ---------------------------------------------------------------- 図 2: 孤児率

def figure_orphan_rate(path: str) -> None:
    """伝播遅延を振って孤児率を測り、棒グラフにする。"""
    ratios = [0.0, 0.02, 0.05, 0.10, 0.20, 0.35, 0.50, 0.75, 1.00]
    rows = []
    for r in ratios:
        net = Network(node_count=6, difficulty=10, latency=30.0 * r,
                      block_interval=30.0, seed=1234)
        net.run(60)
        net.settle()
        rows.append((r, net.stats()["orphan_rate"]))

    width, height = 720, 96 + len(rows) * 30 + 44
    x0, bar_w = 108, 470
    top = 92
    peak = max(v for _, v in rows) or 0.01

    parts = []
    for i, (ratio, rate) in enumerate(rows):
        y = top + i * 30
        parts.append(text(x0 - 12, y + 15, f"{ratio * 100:.0f}%", fill=DIM,
                          size=11.5, family=MONO, anchor="end"))
        parts.append(f'<rect x="{x0}" y="{y + 3}" width="{bar_w}" height="16" '
                     f'rx="4" fill="{PANEL}"/>')
        w = max(2, bar_w * rate / peak)
        col = CANON if rate < 0.02 else (WARN if rate < 0.2 else ORPHAN)
        parts.append(f'<rect x="{x0}" y="{y + 3}" width="{w:.1f}" height="16" '
                     f'rx="4" fill="{col}" fill-opacity="0.85"/>')
        parts.append(text(x0 + bar_w + 14, y + 15, f"{rate * 100:.1f}%",
                          fill=TEXT, size=11.5, family=MONO))

    note_y = height - 18
    parts.append(f'<line x1="22" y1="{note_y - 20}" x2="{width - 22}" '
                 f'y2="{note_y - 20}" stroke="{LINE}"/>')
    parts.append(text(22, note_y - 2,
                      "縦軸 = 伝播遅延 ÷ ブロック間隔　"
                      "Bitcoin は 10 分間隔・数秒の伝播なので、いちばん上の帯にいる",
                      fill=DIM, size=11))

    svg = frame(width, height, "\n".join(parts),
                "伝播遅延と孤児率 — 誰も攻撃していなくても分岐する",
                "ノード 6 台・60 ブロックを、遅延を変えて走らせた実測値")
    _write(path, svg)
    return rows


# ---------------------------------------------------------------- 図 3: 確認数

def figure_confirmations(path: str) -> None:
    """中本論文 11 節の式で、確認数ごとの逆転確率を色分けする。"""
    qs = [0.05, 0.10, 0.25, 0.35, 0.45]
    zs = [0, 1, 2, 3, 4, 6, 8, 12, 24]

    cw, ch = 108, 32
    x0, top = 92, 108
    width = x0 + cw * len(qs) + 30
    height = top + ch * len(zs) + 56

    parts = [text(22, top - 12, "確認数 z", fill=DIM, size=11)]
    for j, q in enumerate(qs):
        parts.append(text(x0 + cw * j + cw / 2, top - 12,
                          f"攻撃者 {q * 100:.0f}%", fill=DIM, size=11,
                          anchor="middle"))

    for i, z in enumerate(zs):
        y = top + i * ch
        parts.append(text(x0 - 14, y + 21, str(z), fill=TEXT, size=12,
                          family=MONO, anchor="end"))
        for j, q in enumerate(qs):
            p = attacker_success_probability(q, z)
            # 10^-6 を安全、1.0 を危険として濃さを決める
            import math
            risk = min(1.0, max(0.0, math.log10(p + 1e-16) / 6 + 1))
            x = x0 + cw * j
            parts.append(f'<rect x="{x + 2}" y="{y + 3}" width="{cw - 4}" '
                         f'height="{ch - 6}" rx="5" fill="{ORPHAN}" '
                         f'fill-opacity="{risk * 0.5:.3f}" stroke="{LINE}"/>')
            label = f"{p * 100:.1f}%" if p >= 0.001 else f"{p:.0e}"
            parts.append(text(x + cw / 2, y + 21, label,
                              fill=TEXT if risk > 0.3 else DIM,
                              size=11.5, family=MONO, anchor="middle"))

    note_y = height - 16
    parts.append(f'<line x1="22" y1="{note_y - 22}" x2="{width - 22}" '
                 f'y2="{note_y - 22}" stroke="{LINE}"/>')
    parts.append(text(22, note_y - 4,
                      "z=0（未確認）はどんな弱い攻撃者でも 100%。"
                      "50% を超えると、いくら待っても 1 に張り付く",
                      fill=DIM, size=11))

    svg = frame(width, height, "\n".join(parts),
                "何確認待てば安全か — 中本論文 (2008) 第 11 節",
                "攻撃者のハッシュ力ごとに、z 確認を覆される確率")
    _write(path, svg)


# ---------------------------------------------------------------- 図 4: 決済の状態

def figure_payment_states(path: str) -> None:
    """請求書の状態遷移。reversed の存在がこの方式の要点。

    これだけは実測ではなく構造の図。ただし状態名と遷移条件は
    chain/payment.py の実装から直接持ってきている。
    """
    BW, BH = 132, 46
    X0, ROW1, ROW2 = 26, 92, 196

    main = [("created", "発行しただけ", CANON_FILL, DIM),
            ("detected", "mempool で発見", "#3a2c14", WARN),
            ("confirming", "ブロックに入った", "#152a44", "#6aa6ff"),
            ("settled", "必要確認数に到達", CANON_FILL, CANON)]
    side = [("expired", 0, "期限切れ", "#1c2233", DIM),
            ("underpaid", 2, "金額が足りない", "#241c3a", "#a98bff"),
            ("reversed", 3, "リオーグで消えた", ORPHAN_FILL, ORPHAN)]

    def bx(i):
        return X0 + i * (BW + 38)

    parts = []

    # 本線の矢印
    for i in range(len(main) - 1):
        x1, x2 = bx(i) + BW, bx(i + 1)
        y = ROW1 + BH / 2
        parts.append(f'<path d="M{x1},{y} L{x2 - 7},{y}" stroke="{LINE}" '
                     f'stroke-width="2" fill="none"/>')
        parts.append(f'<path d="M{x2 - 8},{y - 4} L{x2},{y} L{x2 - 8},{y + 4} Z" '
                     f'fill="{LINE}"/>')

    # 下段への矢印
    for name, i, _, _, _ in side:
        x = bx(i) + BW / 2
        parts.append(f'<path d="M{x},{ROW1 + BH} L{x},{ROW2 - 8}" stroke="{LINE}" '
                     f'stroke-width="2" fill="none" stroke-dasharray="4 3"/>')
        parts.append(f'<path d="M{x - 4},{ROW2 - 9} L{x},{ROW2} L{x + 4},{ROW2 - 9} Z" '
                     f'fill="{LINE}"/>')
    # confirming からも reversed へ落ちる
    xa, xb = bx(2) + BW / 2 + 26, bx(3) + BW / 2 - 26
    parts.append(f'<path d="M{xa},{ROW1 + BH + 6} C{xa + 30},{ROW2 - 20} '
                 f'{xb - 30},{ROW2 - 20} {xb},{ROW2 - 6}" stroke="{ORPHAN}" '
                 f'stroke-opacity="0.5" stroke-width="1.6" fill="none" '
                 f'stroke-dasharray="4 3"/>')

    def box(x, y, name, sub, fill, edge, emphasize=False):
        out = [f'<rect x="{x}" y="{y}" width="{BW}" height="{BH}" rx="9" '
               f'fill="{fill}" stroke="{edge}" '
               f'stroke-width="{2.4 if emphasize else 1.3}"/>',
               text(x + BW / 2, y + 20, name, fill=edge, size=12.5,
                    family=MONO, anchor="middle", weight="600"),
               text(x + BW / 2, y + 35, sub, fill=DIM, size=10, anchor="middle")]
        return out

    for i, (name, sub, fill, edge) in enumerate(main):
        parts += box(bx(i), ROW1, name, sub, fill, edge,
                     emphasize=(name == "settled"))
    for name, i, sub, fill, edge in side:
        parts += box(bx(i), ROW2, name, sub, fill, edge,
                     emphasize=(name == "reversed"))

    # 注釈
    parts.append(text(bx(1) + BW / 2, ROW1 - 12, "0 確認 — 渡してはいけない",
                      fill=WARN, size=10.5, anchor="middle"))
    parts.append(text(bx(3) + BW / 2, ROW1 - 12, "ここで渡す",
                      fill=CANON, size=10.5, anchor="middle", weight="600"))
    parts.append(text(bx(3) + BW + 14, ROW2 + 20,
                      "この方式に固有の状態。", fill=ORPHAN, size=10.5))
    parts.append(text(bx(3) + BW + 14, ROW2 + 35,
                      "誰の意思でもなく起きるので、", fill=DIM, size=10.5))
    parts.append(text(bx(3) + BW + 14, ROW2 + 49,
                      "事後に取り返す手段がない。", fill=DIM, size=10.5))

    width = bx(3) + BW + 210
    height = ROW2 + BH + 66
    note_y = height - 20
    parts.append(f'<line x1="26" y1="{note_y - 20}" x2="{width - 26}" '
                 f'y2="{note_y - 20}" stroke="{LINE}"/>')
    parts.append(text(26, note_y - 2,
                      "確認が積まれるほど期待損失（= 覆される確率 × 金額）が下がる。"
                      "どこで止めるかを決めるのが決済システムの仕事",
                      fill=DIM, size=11))

    svg = frame(width, height, "\n".join(parts),
                "請求書の状態 — いつ商品を渡してよいか",
                "chain/payment.py の実装そのまま。settled 以外では引き渡せない")
    _write(path, svg)


# ---------------------------------------------------------------- 出力

def _write(path: str, svg: str) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(svg)
    print(f"  書き出し: {path}  ({len(svg):,} バイト)")


def main() -> None:
    enable_utf8_stdout()
    here = os.path.dirname(os.path.abspath(__file__))
    default_out = os.path.join(here, "..", "docs", "img")

    ap = argparse.ArgumentParser(description="README 用の図を生成する")
    ap.add_argument("--out", default=default_out, help="出力先ディレクトリ")
    args = ap.parse_args()
    out = os.path.abspath(args.out)

    print("チェーンを実際に走らせて図を作ります。")
    result = figure_reorg(os.path.join(out, "reorg.svg"))
    print(f"    → 攻撃 {'成功' if result['succeeded'] else '失敗'}、"
          f"孤児 {result['hidden_blocks']} ブロック分の枝を捨てさせた")
    rows = figure_orphan_rate(os.path.join(out, "orphan-rate.svg"))
    print(f"    → 孤児率 {rows[0][1]:.1%}（遅延 0）から "
          f"{rows[-1][1]:.1%}（遅延 = ブロック間隔）まで")
    figure_confirmations(os.path.join(out, "confirmations.svg"))
    figure_payment_states(os.path.join(out, "payment-states.svg"))
    print("完了。")


if __name__ == "__main__":
    main()
