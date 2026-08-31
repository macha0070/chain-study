/* chain-study pay — レジ画面
 *
 * 状態はサーバ側の PaymentProcessor が唯一の真実。
 * ここは /api/pos/state を読んで描くだけ。
 * 「入金しました」をクライアント側で判定しないのは、実物の決済でも同じ。
 */

const $ = (s) => document.querySelector(s);
const el = (tag, cls, text) => {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined) n.textContent = text;
  return n;
};

const STATUS_JA = {
  created: '未着', detected: '0 確認', confirming: '確認中',
  settled: '確定', underpaid: '不足', expired: '期限切れ', reversed: '巻き戻り',
};

let state = null;
let timer = null;
let lastResultKey = null;

async function api(path, body) {
  const opts = body
    ? { method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body) }
    : {};
  return (await fetch(path, opts)).json();
}

async function refresh() {
  try {
    state = await api('/api/pos/state');
    render();
  } catch (e) {
    console.error(e);
  }
  clearTimeout(timer);
  const running = state && state.job && state.job.running;
  timer = setTimeout(refresh, running ? 350 : 2000);
}

/* ------------------------------------------------------------- 描画 */

function render() {
  renderStats();
  renderOrders();
  renderCustomers();
  renderPolicy();
  renderLog();
  renderJob();
  renderAttackTargets();
}

function renderStats() {
  const s = state.summary;
  const chips = [
    ['高さ', state.height, ''],
    ['注文', s.invoices, ''],
    ['引き渡し', s.released, ''],
    ['巻き戻り', s.reversed_after_release,
      s.reversed_after_release > 0 ? 'bad' : ''],
    ['損失', s.lost_amount, s.lost_amount > 0 ? 'bad' : ''],
  ];
  $('#stats').replaceChildren(...chips.map(([label, v, cls]) => {
    const c = el('div', 'chip' + (cls ? ' ' + cls : ''));
    c.append(el('b', null, String(v)), el('span', null, label));
    return c;
  }));

  const sum = $('#summary');
  sum.replaceChildren();
  const parts = [
    ['注文', s.invoices, ''],
    ['引き渡し済み', s.released, ''],
    ['渡したあと巻き戻り', s.reversed_after_release,
      s.reversed_after_release > 0 ? 'bad' : ''],
    ['損失', s.lost_amount, s.lost_amount > 0 ? 'bad' : ''],
  ];
  parts.forEach(([k, v, cls]) => {
    const sp = el('span', cls);
    sp.append(k + ' ', el('b', null, String(v)));
    sum.append(sp);
  });
}

function riskClass(loss, amount) {
  if (loss >= amount * 0.2) return 'risk-high';
  if (loss >= 1) return 'risk-mid';
  return 'risk-low';
}

function renderOrders() {
  const box = $('#orders');
  if (!state.invoices.length) {
    box.replaceChildren(el('div', 'empty', 'まだ請求書がありません'));
    return;
  }

  box.replaceChildren(...state.invoices.map(inv => {
    const card = el('div', 'order s-' + inv.status);

    const top = el('div', 'order-top');
    top.append(el('span', 'order-id', '#' + inv.id),
               el('span', 'order-amount', String(inv.amount)),
               el('span', 'order-memo', inv.memo || ''),
               el('span', 'badge ' + inv.status,
                  STATUS_JA[inv.status] || inv.status));
    card.append(top);

    card.append(el('div', 'order-addr', '支払先 ' + inv.address +
      (inv.txid ? '   tx ' + inv.txid + '…' : '')));

    // 確認の積み上がりを、必要数ぶんのマスで見せる
    const bar = el('div', 'confbar');
    const slots = Math.max(inv.required, 1);
    for (let i = 0; i < slots; i++) {
      const cell = el('i');
      if (inv.status === 'reversed') cell.className = 'lost';
      else if (i < inv.confirmations) {
        cell.className = inv.confirmations >= inv.required ? 'done' : 'on';
      }
      bar.append(cell);
    }
    card.append(bar);

    const m = el('div', 'order-metrics');
    const conf = el('span');
    conf.append('確認 ', el('b', null, `${inv.confirmations} / ${inv.required}`));
    const loss = el('span', riskClass(inv.expected_loss, inv.amount));
    loss.append('期待損失 ', el('b', null, inv.expected_loss.toFixed(2)));
    const risk = el('span');
    risk.append('覆される確率 ', el('b', null,
      inv.risk >= 0.001 ? (inv.risk * 100).toFixed(1) + '%' : inv.risk.toExponential(1)));
    m.append(conf, loss, risk);
    if (inv.received && inv.received !== inv.amount) {
      const r = el('span');
      r.append('受領 ', el('b', null, String(inv.received)));
      m.append(r);
    }
    card.append(m);

    const actions = el('div', 'order-actions');
    const released = state.released.includes(inv.id);

    if (!released) {
      const pay = el('button', null, 'Alice が支払う');
      pay.disabled = !['created', 'expired'].includes(inv.status);
      pay.addEventListener('click', async () => {
        const r = await api('/api/pos/pay', { invoice_id: inv.id, from: 'Alice' });
        if (!r.ok) alert(r.error);
        refresh();
      });
      actions.append(pay);

      const rel = el('button', inv.safe ? 'primary' : '', '商品を引き渡す');
      rel.disabled = !inv.safe;
      rel.title = inv.safe ? '' : `まだ ${STATUS_JA[inv.status]}（${inv.confirmations}/${inv.required} 確認）`;
      rel.addEventListener('click', async () => {
        await api('/api/pos/release', { invoice_id: inv.id });
        refresh();
      });
      actions.append(rel);

      if (!inv.safe && ['detected', 'confirming'].includes(inv.status)) {
        const force = el('button', 'danger', '待たずに渡す');
        force.title = '本来のポリシーを無視して引き渡す';
        force.addEventListener('click', async () => {
          await api('/api/pos/release', { invoice_id: inv.id, force: true });
          refresh();
        });
        actions.append(force);
      }
    } else if (inv.status === 'reversed') {
      actions.append(el('span', 'lost',
        `⚠ 引き渡し済み。支払いは消えた（損失 ${inv.amount}）`));
    } else {
      actions.append(el('span', 'released', '✓ 引き渡し済み'));
    }
    card.append(actions);

    if (inv.history.length) {
      const hist = el('div', 'order-history');
      inv.history.slice(-4).forEach((h, i, arr) => {
        const row = el('div', i === arr.length - 1 ? 'now' : '');
        row.textContent = `[${h.t.toFixed(1)}s] ${h.text}`;
        hist.append(row);
      });
      card.append(hist);
    }

    return card;
  }));
}

function renderCustomers() {
  $('#customers').replaceChildren(...state.customers.map(c => {
    const row = el('div', 'customer' + (c.balance === 0 ? ' zero' : ''));
    row.append(el('span', null, c.name), el('b', null, String(c.balance)));
    return row;
  }));
}

/* 現在のスライダー設定で、いま入力中の金額が何確認になるか */
function renderPolicy() {
  const amount = Number($('#amount').value) || 1;
  const q = Number($('#attacker').value) / 100;
  const tol = Number($('#tolerated').value);

  // 中本論文の式をそのままフロントでも回す（表示用。判定はサーバ側）
  const P = (q, z) => {
    const p = 1 - q;
    if (q >= p) return 1;
    const lam = z * (q / p);
    let total = 0, fact = 1;
    for (let k = 0; k <= z; k++) {
      if (k > 0) fact *= k;
      total += (Math.exp(-lam) * Math.pow(lam, k) / fact) *
               (1 - Math.pow(q / p, z - k));
    }
    return 1 - total;
  };
  let z = 24;
  for (let i = 0; i <= 24; i++) {
    if (P(q, i) * amount <= tol) { z = Math.max(i, 1); break; }
  }

  const box = $('#policy-preview');
  box.replaceChildren();
  box.append(document.createTextNode(`${amount} を受け取るなら `));
  box.append(el('b', null, `${z} 確認`));
  box.append(document.createTextNode(
    ` 待つ（そのときの期待損失 ${(P(q, z) * amount).toFixed(3)}）`));

  const table = $('#policy-table');
  table.replaceChildren();
  const head = el('tr');
  head.append(el('th', null, '金額'), el('th', null, '必要確認数'),
              el('th', null, '期待損失'));
  table.append(head);
  (state.policy_table || []).forEach(r => {
    const tr = el('tr', r.amount === amount ? 'here' : '');
    tr.append(el('td', null, r.amount.toLocaleString()),
              el('td', null, String(r.required)),
              el('td', null, r.loss.toFixed(3)));
    table.append(tr);
  });
}

function renderLog() {
  $('#log').replaceChildren(...[...state.log].reverse().map(e => {
    const row = el('div', 'k-' + e.kind);
    row.append(el('span', 't', e.t.toFixed(1) + 's'), el('span', 'm', e.text));
    return row;
  }));
}

function renderJob() {
  const box = $('#job');
  const job = state.job;
  const running = !!(job && job.running);
  document.querySelectorAll('button[data-mine], #attack')
    .forEach(b => { b.disabled = running; });

  if (job && !running && job.result) {
    const key = JSON.stringify(job.result);
    if (key !== lastResultKey) { lastResultKey = key; showResult(job.result); }
  }

  if (!job || (!running && !job.error)) { box.hidden = true; return; }
  box.hidden = false;
  box.replaceChildren();
  if (job.error) {
    const e = el('div', null, '⚠ ' + job.error);
    e.style.color = 'var(--danger)';
    box.append(e);
    return;
  }
  box.append(el('div', null, job.step ? `${job.label} … ${job.step}` : job.label));
  const bar = el('div', 'bar'), fill = el('i');
  fill.style.width = job.total
    ? Math.min(100, job.done / job.total * 100) + '%' : '30%';
  bar.append(fill);
  box.append(bar);
}

function renderAttackTargets() {
  const sel = $('#attack-target');
  const prev = sel.value;
  const targets = state.invoices.filter(
    i => !['reversed', 'expired', 'settled'].includes(i.status));
  sel.replaceChildren(...targets.map(i => {
    const o = el('option', null,
      `#${i.id}  ${i.amount}  ${i.memo || ''}`.trim());
    o.value = i.id;
    return o;
  }));
  if (!targets.length) {
    sel.append(el('option', null, '狙える注文がありません'));
    $('#attack').disabled = true;
  } else {
    $('#attack').disabled = !!(state.job && state.job.running);
    if (prev && [...sel.options].some(o => o.value === prev)) sel.value = prev;
  }
}

function showResult(r) {
  const box = $('#attack-result');
  box.replaceChildren();
  if (!r || !r.ok) return;
  const ok = r.verdict.startsWith('成功');
  box.append(el('div', 'verdict ' + (ok ? 'ok' : 'fail'), '結果: ' + r.verdict));
  const dl = el('dl', 'kv');
  r.rows.forEach(([k, v]) => {
    dl.append(el('dt', null, k), el('dd', null, v));
  });
  box.append(dl);
  if (r.note) box.append(el('div', 'result-note', r.note));
}

/* ------------------------------------------------------------- 操作 */

$('#issue').addEventListener('click', async () => {
  const r = await api('/api/pos/invoice', {
    amount: Number($('#amount').value),
    memo: $('#memo').value,
    attacker_share: Number($('#attacker').value) / 100,
    tolerated_loss: Number($('#tolerated').value),
  });
  if (!r.ok) alert(r.error);
  refresh();
});

$('#faucet').addEventListener('click', async () => {
  const r = await api('/api/faucet', { wallet: 'Alice', amount: 100 });
  if (!r.ok) alert(r.error + '\n先に採掘してください。');
  refresh();
});

document.querySelectorAll('button[data-mine]').forEach(b => {
  b.addEventListener('click', async () => {
    await api('/api/mine', { count: Number(b.dataset.mine) });
    refresh();
  });
});

$('#attack').addEventListener('click', async () => {
  const id = Number($('#attack-target').value);
  if (!id) return;
  $('#attack-result').replaceChildren(el('div', 'result-note', '実行中…'));
  await api('/api/pos/attack', {
    invoice_id: id,
    release_at: Number($('#release-at').value),
  });
  refresh();
});

['amount', 'attacker', 'tolerated'].forEach(id => {
  $('#' + id).addEventListener('input', () => {
    $('#q-val').textContent = $('#attacker').value + '%';
    $('#loss-val').textContent = Number($('#tolerated').value).toFixed(2);
    if (state) renderPolicy();
  });
});

$('#release-at').addEventListener('input', () => {
  $('#release-val').textContent = $('#release-at').value;
});

refresh();
