/* chain-study lab — フロントエンド
 *
 * 状態はサーバ側の Lab オブジェクトが唯一の真実。
 * ここは /api/state を読んで描くだけで、ローカルに状態を持たない。
 * 持つと必ずズレるし、ズレたときに「チェーンが壊れたのか UI が壊れたのか」
 * が分からなくなる。
 */

const $ = (sel) => document.querySelector(sel);
const el = (tag, cls, text) => {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined) n.textContent = text;
  return n;
};

const TIP_COLORS = ['#56d39a', '#6aa6ff', '#f0b64e', '#a98bff', '#ff8fb1', '#5fd0d8'];

let state = null;
let selected = null;
let pollTimer = null;

/* ------------------------------------------------------------- 通信 */

async function api(path, body) {
  const opts = body
    ? { method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body) }
    : {};
  const res = await fetch(path, opts);
  return res.json();
}

async function refresh() {
  try {
    state = await api('/api/state');
    render();
    schedule();
  } catch (e) {
    console.error(e);
    schedule(3000);
  }
}

function schedule(ms) {
  clearTimeout(pollTimer);
  const running = state && state.job && state.job.running;
  pollTimer = setTimeout(refresh, ms || (running ? 350 : 2500));
}

/* ------------------------------------------------------------- 描画 */

function render() {
  renderStats();
  renderNodes();
  renderWallets();
  renderGraph();
  renderLog();
  renderJob();
  renderWalletSelects();
  syncControls();
}

function renderStats() {
  const s = state.stats;
  const obs = state.nodes[0];
  const chips = [
    ['高さ', obs.height, ''],
    ['ブロック総数', s.total_blocks, ''],
    ['孤児', s.orphans, s.orphans > 0 ? 'bad' : ''],
    ['孤児率', (s.orphan_rate * 100).toFixed(1) + '%', s.orphan_rate > 0.1 ? 'bad' : ''],
    ['UTXO', state.utxo_count, ''],
    ['合意', s.converged ? '一致' : '分裂中', s.converged ? 'good' : 'bad'],
    ['伝送中', s.in_flight, ''],
    ['模擬時刻', s.time.toFixed(0) + 's', ''],
  ];
  $('#stats').replaceChildren(...chips.map(([label, val, cls]) => {
    const c = el('div', 'chip' + (cls ? ' ' + cls : ''));
    c.append(el('b', null, String(val)), el('span', null, label));
    return c;
  }));
}

/* tip ハッシュごとに色を割り当てる。同じ色 = 同じ意見。 */
function tipColorMap() {
  const tips = [...new Set(state.nodes.map(n => n.tip))];
  const map = {};
  tips.forEach((t, i) => { map[t] = TIP_COLORS[i % TIP_COLORS.length]; });
  return map;
}

function renderNodes() {
  const colors = tipColorMap();
  const maxRate = Math.max(...state.nodes.map(n => n.hashrate));
  $('#nodes').replaceChildren(...state.nodes.map(n => {
    const box = el('div', 'node');
    box.style.setProperty('--tipcolor', colors[n.tip] || '#5c6880');

    const top = el('div', 'node-top');
    top.append(el('span', 'node-name', n.name),
               el('span', 'node-tip', n.tip ? n.tip.slice(0, 8) : '—'));

    const meta = el('div', 'node-meta');
    [['高さ', n.height], ['採掘', n.mined], ['mempool', n.mempool],
     ['保留', n.orphan_pool], ['残高', n.balance]].forEach(([k, v]) => {
      const s = el('span'); s.append(k + ' ', el('b', null, String(v)));
      meta.append(s);
    });

    const bar = el('div', 'hashbar');
    const fill = el('i');
    fill.style.width = (n.hashrate / maxRate * 100) + '%';
    bar.append(fill);

    box.append(top, meta, bar);
    return box;
  }));
}

function renderWallets() {
  const order = { user: 0, miner: 1 };
  const sorted = [...state.wallets].sort(
    (a, b) => order[a.kind] - order[b.kind] || b.balance - a.balance);
  $('#wallets').replaceChildren(...sorted.map(w => {
    const row = el('div', 'wallet ' + w.kind + (w.balance === 0 ? ' zero' : ''));
    const left = el('div');
    left.append(el('div', 'w-name', w.name), el('div', 'w-addr', w.address));
    row.append(left, el('div', 'w-bal', String(w.balance)));
    return row;
  }));
}

/* ---- チェーンの図。x = 高さ, y = レーン（分岐ごとに 1 本） ---- */

function renderGraph() {
  const box = $('#graph');
  const blocks = state.blocks;
  if (!blocks.length) {
    box.replaceChildren(el('div', 'empty', 'まだブロックがありません'));
    return;
  }

  const W = 86, H = 64, BW = 62, BH = 40, PAD = 14;
  const maxH = Math.max(...blocks.map(b => b.height));
  const maxLane = Math.max(...blocks.map(b => b.lane));
  const width = PAD * 2 + (maxH + 1) * W;
  const height = PAD * 2 + (maxLane + 1) * H;
  const pos = {};
  blocks.forEach(b => {
    pos[b.hash] = { x: PAD + b.height * W, y: PAD + b.lane * H };
  });

  const NS = 'http://www.w3.org/2000/svg';
  const svg = document.createElementNS(NS, 'svg');
  svg.setAttribute('width', width);
  svg.setAttribute('height', height);
  svg.setAttribute('viewBox', `0 0 ${width} ${height}`);

  // 辺（親 → 子）
  blocks.forEach(b => {
    const p = pos[b.prev], c = pos[b.hash];
    if (!p) return;
    const path = document.createElementNS(NS, 'path');
    const x1 = p.x + BW, y1 = p.y + BH / 2, x2 = c.x, y2 = c.y + BH / 2;
    const mx = (x1 + x2) / 2;
    path.setAttribute('d', `M${x1},${y1} C${mx},${y1} ${mx},${y2} ${x2},${y2}`);
    path.setAttribute('fill', 'none');
    path.setAttribute('stroke', b.canonical ? '#2f6b52' : '#4a2b33');
    path.setAttribute('stroke-width', b.canonical ? 2 : 1.5);
    svg.append(path);
  });

  const colors = tipColorMap();

  blocks.forEach(b => {
    const { x, y } = pos[b.hash];
    const g = document.createElementNS(NS, 'g');
    g.setAttribute('class', 'blk');
    g.setAttribute('transform', `translate(${x},${y})`);

    const rect = document.createElementNS(NS, 'rect');
    rect.setAttribute('width', BW); rect.setAttribute('height', BH);
    rect.setAttribute('rx', 7);
    rect.setAttribute('fill', b.canonical ? '#17352a' : '#2b1a1f');
    rect.setAttribute('stroke',
      selected === b.hash ? '#e7edf7'
        : b.tip_of.length ? (colors[b.hash] || '#6aa6ff')
        : (b.canonical ? '#2f6b52' : '#5a3038'));
    rect.setAttribute('stroke-width', b.tip_of.length || selected === b.hash ? 2 : 1);
    g.append(rect);

    const hash = document.createElementNS(NS, 'text');
    hash.setAttribute('x', BW / 2); hash.setAttribute('y', 16);
    hash.setAttribute('text-anchor', 'middle');
    hash.setAttribute('fill', b.canonical ? '#8ee6be' : '#e39a9a');
    hash.textContent = b.short;
    g.append(hash);

    const meta = document.createElementNS(NS, 'text');
    meta.setAttribute('x', BW / 2); meta.setAttribute('y', 29);
    meta.setAttribute('text-anchor', 'middle');
    meta.setAttribute('fill', '#7a8699');
    meta.textContent = `#${b.height} · ${b.txs}tx`;
    g.append(meta);

    if (b.tip_of.length) {
      const tips = document.createElementNS(NS, 'text');
      tips.setAttribute('x', BW / 2); tips.setAttribute('y', BH + 12);
      tips.setAttribute('text-anchor', 'middle');
      tips.setAttribute('fill', colors[b.hash] || '#6aa6ff');
      tips.textContent = b.tip_of.map(i => String.fromCharCode(65 + i)).join(' ');
      g.append(tips);
    }

    g.addEventListener('click', () => showDetail(b.hash));
    svg.append(g);
  });

  box.replaceChildren(svg);
  // 新しいブロックが右端に出るので、追従してスクロールする
  box.scrollLeft = box.scrollWidth;
}

function renderLog() {
  const kinds = { block: 'k-block', reorg: 'k-reorg', tx: 'k-tx',
                  attack: 'k-attack' };
  $('#log').replaceChildren(...[...state.log].reverse().map(e => {
    const row = el('div', kinds[e.kind] || '');
    row.append(el('span', 't', e.t.toFixed(1) + 's'),
               el('span', 'm', e.text));
    return row;
  }));
}

let lastResultKey = null;

function renderJob() {
  const box = $('#job');
  const job = state.job;
  const running = !!(job && job.running);

  // 走っている間だけ操作を止める。早期 return より前に置くこと
  // （後ろに置くと、ジョブ完了後にボタンが無効のまま戻らない）。
  document.querySelectorAll('button[data-mine], button[data-attack]')
    .forEach(b => { b.disabled = running; });

  // 完了したジョブの結果は一度だけ出す。毎ポーリングで描き直すと、
  // 読んでいる途中に内容が入れ替わって落ち着かない。
  if (job && !running && job.result) {
    const key = JSON.stringify(job.result);
    if (key !== lastResultKey) { lastResultKey = key; showAttackResult(job.result); }
  }

  if (!job || (!running && !job.error)) { box.hidden = true; return; }
  box.hidden = false;
  box.replaceChildren();
  if (job.error) {
    const err = el('div', null, '⚠ ' + job.error);
    err.style.color = 'var(--danger)';
    box.append(err);
    return;
  }
  box.append(el('div', null,
    job.step ? `${job.label} … ${job.step}` : `${job.label} … ${job.done}/${job.total || '?'}`));
  const bar = el('div', 'bar'), fill = el('i');
  fill.style.width = job.total
    ? Math.min(100, job.done / job.total * 100) + '%' : '30%';
  bar.append(fill);
  box.append(bar);
}

/* サーバ側の設定を操作パネルに反映する。
   触っている最中の入力だけは上書きしない（つまみと喧嘩するため）。 */
function syncControls() {
  const active = document.activeElement ? document.activeElement.id : '';
  const c = state.config;
  const pairs = [['latency', c.latency], ['interval', c.interval],
                 ['nodes-n', c.nodes], ['diff-n', c.difficulty]];
  pairs.forEach(([id, v]) => { if (active !== id) $('#' + id).value = v; });
  $('#lat-val').textContent = Number(c.latency).toFixed(1);
  $('#int-val').textContent = c.interval;
  ratioHint();
}

function renderWalletSelects() {
  ['#send-from', '#send-to'].forEach((sel, i) => {
    const node = $(sel);
    const prev = node.value;
    node.replaceChildren(...state.wallets.map(w => {
      const o = el('option', null, `${w.name} (${w.balance})`);
      o.value = w.name;
      return o;
    }));
    if (prev && [...node.options].some(o => o.value === prev)) node.value = prev;
    else if (state.wallets.length) node.value = state.wallets[i === 0 ? 0 : 1]?.name || '';
  });
}

/* ------------------------------------------------------------- 詳細 */

async function showDetail(hash) {
  selected = hash;
  const d = await api('/api/block?hash=' + hash);
  if (!d.ok) return;
  const box = $('#detail');
  const dl = el('dl');
  const rows = [
    ['高さ', String(d.height)],
    ['状態', d.canonical ? '正典チェーン' : '孤児（別の枝）'],
    ['hash', d.hash],
    ['前ブロック', d.prev === '0'.repeat(64) ? '(genesis)' : d.prev],
    ['マークル根', d.merkle_root],
    ['難易度', `${d.difficulty} ビット（実際の先頭 0 は ${d.leading_zeros}）`],
    ['nonce', d.nonce.toLocaleString()],
  ];
  rows.forEach(([k, v]) => { dl.append(el('dt', null, k), el('dd', null, v)); });
  box.replaceChildren(dl);

  const list = el('div', 'txlist');
  d.txs.forEach(t => {
    const row = el('div', 'txrow');
    const head = el('div');
    head.append(el('span', 'txid', t.txid.slice(0, 24) + '…'));
    if (t.coinbase) head.append(el('span', 'tag cb', 'coinbase 新規発行'));
    row.append(head);
    row.append(el('div', 'io',
      '入力: ' + (t.inputs.length ? t.inputs.join(', ') : '(なし)')));
    row.append(el('div', 'io',
      '出力: ' + t.outputs.map(o => `${o.amount} → ${o.address}`).join(', ')));
    list.append(row);
  });
  box.append(list);
  $('#detail-panel').hidden = false;
  renderGraph();
}

/* ------------------------------------------------------------- 攻撃結果 */

function showAttackResult(r) {
  const box = $('#attack-result');
  box.replaceChildren();
  if (!r || !r.ok) {
    if (r && r.error) {
      const e = el('div', 'result-note', '⚠ ' + r.error);
      e.style.color = 'var(--danger)';
      box.append(e);
    }
    return;
  }

  if (r.verdict) {
    const ok = !r.verdict.startsWith('失敗');
    box.append(el('div', 'verdict ' + (ok ? 'ok' : 'fail'), '結果: ' + r.verdict));
  }

  if (r.rows) {
    const dl = el('dl', 'kv');
    r.rows.forEach(([k, v]) => {
      dl.append(el('dt', null, k),
                el('dd', null, v.length > 34 ? v.slice(0, 14) + '…' + v.slice(-14) : v));
    });
    box.append(dl);
  }

  if (r.chart) {
    const wrap = el('div', 'sweep');
    const max = Math.max(...r.chart.map(c => c.rate), 0.01);
    r.chart.forEach(c => {
      const row = el('div', 'bar-row');
      const track = el('div', 'bar-track'), fill = el('div', 'bar-fill');
      fill.style.width = (c.rate / max * 100) + '%';
      track.append(fill);
      row.append(el('div', 'bar-label', (c.ratio * 100).toFixed(0) + '%'),
                 track,
                 el('div', 'bar-val', (c.rate * 100).toFixed(1) + '%'));
      wrap.append(row);
    });
    const cap = el('div', 'result-note', '横軸ラベル = 伝播遅延 / ブロック間隔、棒 = 孤児率');
    box.append(wrap, cap);
  }

  if (r.grid) {
    const table = el('table', 'conf');
    const head = el('tr');
    head.append(el('th', null, 'z＼q'), ...r.qs.map(q => el('th', null, (q * 100) + '%')));
    table.append(head);
    r.zs.forEach((z, i) => {
      const tr = el('tr');
      tr.append(el('th', null, String(z)));
      r.grid[i].forEach(p => {
        const td = el('td', null, p >= 0.01 ? (p * 100).toFixed(1) + '%' : p.toExponential(1));
        const risk = Math.min(1, Math.max(0, Math.log10(p + 1e-16) / 6 + 1));
        td.style.background = `rgba(255,107,107,${(risk * 0.42).toFixed(3)})`;
        tr.append(td);
      });
      table.append(tr);
    });
    box.append(table);
  }

  if (r.note) box.append(el('div', 'result-note', r.note));
}

/* ------------------------------------------------------------- 操作 */

document.querySelectorAll('button[data-mine]').forEach(btn => {
  btn.addEventListener('click', async () => {
    await api('/api/mine', { count: Number(btn.dataset.mine) });
    refresh();
  });
});

$('#settle').addEventListener('click', async () => {
  await api('/api/settle', {}); refresh();
});

$('#send').addEventListener('click', async () => {
  const r = await api('/api/send', {
    from: $('#send-from').value, to: $('#send-to').value,
    amount: Number($('#send-amount').value), fee: Number($('#send-fee').value),
  });
  if (!r.ok) showAttackResult(r);
  refresh();
});

$('#faucet').addEventListener('click', async () => {
  const r = await api('/api/faucet', { wallet: 'Alice', amount: 50 });
  if (!r.ok) showAttackResult(r);
  refresh();
});

$('#reset').addEventListener('click', async () => {
  await api('/api/reset', {
    nodes: Number($('#nodes-n').value),
    difficulty: Number($('#diff-n').value),
    latency: Number($('#latency').value),
    interval: Number($('#interval').value),
  });
  selected = null;
  $('#detail-panel').hidden = true;
  $('#attack-result').replaceChildren();
  refresh();
});

function ratioHint() {
  const lat = Number($('#latency').value), int = Number($('#interval').value);
  const r = lat / int;
  const verdict = r === 0 ? '分岐は起きない'
    : r < 0.05 ? '孤児はほぼ出ない（Bitcoin 本番はこの領域）'
    : r < 0.2 ? '時々分岐する'
    : '頻繁に分岐する。正直者の仕事が捨てられていく';
  $('#ratio-hint').textContent = `遅延 / 間隔 = ${(r * 100).toFixed(0)}% → ${verdict}`;
}

['latency', 'interval'].forEach(id => {
  $('#' + id).addEventListener('input', () => {
    $('#lat-val').textContent = Number($('#latency').value).toFixed(1);
    $('#int-val').textContent = $('#interval').value;
    ratioHint();
  });
  $('#' + id).addEventListener('change', async () => {
    await api('/api/config', {
      latency: Number($('#latency').value),
      interval: Number($('#interval').value),
    });
    refresh();
  });
});

document.querySelectorAll('button[data-attack]').forEach(btn => {
  btn.addEventListener('click', async () => {
    const name = btn.dataset.attack;
    $('#attack-result').replaceChildren(el('div', 'result-note', '実行中…'));
    const r = name === 'confirmations'
      ? await api('/api/confirmations')
      : await api('/api/attack/' + name, {});
    // 同期で結果が返る攻撃と、ジョブとして走る攻撃がある
    if (r.rows || r.grid || r.chart) showAttackResult(r);
    else if (!r.ok) showAttackResult(r);
    else $('#attack-result').replaceChildren(
      el('div', 'result-note', 'ネットワーク上で実行中。ログを見てください。'));
    refresh();
  });
});

$('#detail-close').addEventListener('click', () => {
  $('#detail-panel').hidden = true;
  selected = null;
  renderGraph();
});

ratioHint();
refresh();
