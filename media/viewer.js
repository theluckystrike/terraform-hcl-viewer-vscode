/* global acquireVsCodeApi */
(function () {
  'use strict';
  const vscode = acquireVsCodeApi();
  const app = document.getElementById('app');

  let state = {
    name: '',
    summary: null,
    pageSize: 100,
    page: 0,
    total: 0,
    rows: [],
    selected: null,
    tab: 'blocks',
    req: 0,
  };

  function esc(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function post(msg) {
    state.req += 1;
    vscode.postMessage({ ...msg, req: state.req });
  }

  function fmtSize(n) {
    if (n >= 1048576) return `${(n / 1048576).toFixed(1)} MB`;
    if (n >= 1024) return `${(n / 1024).toFixed(1)} KB`;
    return `${n} B`;
  }

  function renderShell() {
    const s = state.summary;
    const errChip = s.errorCount > 0 ? `<span class="chip bad"><b>Errors:</b> ${s.errorCount}</span>` : '<span class="chip"><b>Errors:</b> 0</span>';
    const warnChip = s.warningCount > 0 ? `<span class="chip warn"><b>Warnings:</b> ${s.warningCount}</span>` : '';
    const unpinChip = s.unpinnedCount > 0 ? `<span class="chip warn"><b>Unpinned:</b> ${s.unpinnedCount}</span>` : '<span class="chip"><b>Pinned:</b> 100%</span>';

    app.innerHTML = `
      <div class="top">
        <div class="title">
          <span class="name">${esc(state.name)}</span>
          <span class="kind">${esc(s.fileKind.toUpperCase())} · ${s.totalLines} lines · ${fmtSize(s.fileSize)} · 100% offline (no Terraform CLI or cloud calls)</span>
        </div>
        <div class="summary">
          <span class="chip"><b>Resources:</b> ${s.resourceCount}</span>
          <span class="chip"><b>Data:</b> ${s.dataCount}</span>
          <span class="chip"><b>Modules:</b> ${s.moduleCount}</span>
          <span class="chip"><b>Variables:</b> ${s.variableCount}</span>
          <span class="chip"><b>Outputs:</b> ${s.outputCount}</span>
          ${unpinChip}${errChip}${warnChip}
        </div>
        <div class="toolbar">
          <input id="q" type="search" placeholder="Filter by resource, module, variable or ref..." />
          <select id="statusFilter">
            <option value="">All blocks</option>
            <option value="resource">Resources</option>
            <option value="module">Modules</option>
            <option value="variable">Variables</option>
            <option value="error">Errors</option>
            <option value="warning">Warnings</option>
            <option value="ok">Clean</option>
          </select>
          <button id="filterBtn" type="button">Filter</button>
          <span class="sep"></span>
          <div id="protools"></div>
        </div>
        <div class="tabs">
          <button class="tab on" data-tab="blocks" type="button">Blocks &amp; Tree (${s.blockCount})</button>
          <button class="tab" data-tab="modules" type="button">Providers &amp; Modules (${s.providerCount + s.moduleCount})</button>
          <button class="tab" data-tab="findings" type="button">Security Findings (${s.errorCount + s.warningCount})</button>
        </div>
        <div id="hint" class="hint"></div>
      </div>
      <div class="main">
        <div id="leftPane" class="tablewrap"></div>
        <div id="detail" class="detail"><p class="muted">Select a block to inspect its attributes, dependency references and security findings.</p></div>
      </div>
      <div class="pager">
        <button id="prev" type="button">Prev</button>
        <span id="pageInfo"></span>
        <button id="next" type="button">Next</button>
      </div>
    `;

    const q = document.getElementById('q');
    const stSel = document.getElementById('statusFilter');
    const runFilter = () => {
      state.page = 0;
      post({ type: 'filter', filter: { text: q.value, status: stSel.value } });
    };
    document.getElementById('filterBtn').addEventListener('click', runFilter);
    q.addEventListener('keydown', (e) => { if (e.key === 'Enter') runFilter(); });
    stSel.addEventListener('change', runFilter);

    document.querySelectorAll('.tab').forEach((btn) => {
      btn.addEventListener('click', () => {
        document.querySelectorAll('.tab').forEach((b) => b.classList.remove('on'));
        btn.classList.add('on');
        state.tab = btn.dataset.tab;
        renderPane();
      });
    });

    document.getElementById('prev').addEventListener('click', () => {
      if (state.page > 0) { state.page -= 1; loadPage(); }
    });
    document.getElementById('next').addEventListener('click', () => {
      if ((state.page + 1) * state.pageSize < state.total) { state.page += 1; loadPage(); }
    });
  }

  function loadPage() {
    post({ type: 'page', from: state.page * state.pageSize, n: state.pageSize });
  }

  function renderPane() {
    const left = document.getElementById('leftPane');
    const pager = document.querySelector('.pager');
    const s = state.summary;

    if (state.tab === 'modules') {
      pager.style.display = 'none';
      const mRows = (s.modules || []).map((m) => `<tr>
        <td class="num">${m.line}</td>
        <td>module</td>
        <td><strong><code>${esc(m.name)}</code></strong></td>
        <td><code>${esc(m.source)}</code></td>
        <td><code>${esc(m.version)}</code></td>
        <td class="${m.status === 'ok' ? 'ok' : ''}">${esc(m.status.toUpperCase())}</td>
      </tr>`).join('');
      const pRows = (s.providers || []).map((p) => `<tr>
        <td class="num">${p.line}</td>
        <td>provider</td>
        <td><strong><code>${esc(p.name)}</code></strong></td>
        <td><code>${esc(p.source)}</code></td>
        <td><code>${esc(p.version)}</code></td>
        <td class="${p.status === 'ok' ? 'ok' : ''}">${esc((p.status || 'ok').toUpperCase())}</td>
      </tr>`).join('');
      left.innerHTML = `<table id="grid">
        <thead><tr><th class="num">Line</th><th>Kind</th><th>Name</th><th>Source</th><th>Version</th><th>Status</th></tr></thead>
        <tbody>${(mRows + pRows) || '<tr><td colspan="6" class="muted">No providers or modules declared.</td></tr>'}</tbody>
      </table>`;
      return;
    }

    if (state.tab === 'findings') {
      pager.style.display = 'none';
      const fRows = (s.findings || []).map((f) => `<tr>
        <td class="${f.severity === 'error' ? 'bad' : ''}">${esc(f.severity.toUpperCase())}</td>
        <td>${esc(f.category)}</td>
        <td><code>${esc(f.rule)}</code></td>
        <td class="num">${f.line}</td>
        <td><code>${esc(f.section)}</code></td>
        <td>${esc(f.message)}</td>
      </tr>`).join('');
      left.innerHTML = fRows
        ? `<table id="grid"><thead><tr><th>Severity</th><th>Category</th><th>Rule</th><th class="num">Line</th><th>Scope</th><th>Finding</th></tr></thead><tbody>${fRows}</tbody></table>`
        : '<p class="muted" style="padding:12px;">All static Terraform HCL security and pinning checks passed.</p>';
      return;
    }

    pager.style.display = 'flex';
    const body = state.rows.map((r) => {
      const sel = state.selected === r.index ? ' class="sel"' : '';
      const eBadge = r.errorCount ? `<span class="badge-mismatch">ERR (${r.errorCount})</span>` : '';
      const wBadge = r.warningCount ? `<span class="badge-muted">WARN (${r.warningCount})</span>` : '';
      const statusCls = r.status === 'error' ? 'bad' : (r.status === 'ok' ? 'ok' : '');
      return `<tr data-idx="${r.index}"${sel}>
        <td class="num">${r.line}</td>
        <td class="num">T${r.depth}</td>
        <td><code>${esc(r.kind)}</code></td>
        <td><strong><code>${esc(r.address)}</code></strong>${eBadge}${wBadge}</td>
        <td><code>${esc(r.source || r.type)}</code></td>
        <td class="num">${r.refCount}</td>
        <td class="${statusCls}">${esc(r.status.toUpperCase())}</td>
      </tr>`;
    }).join('');
    left.innerHTML = `<table id="grid">
      <thead><tr><th class="num">Line</th><th class="num">Tier</th><th>Kind</th><th>Address</th><th>Type / Source</th><th class="num">Refs</th><th>Status</th></tr></thead>
      <tbody>${body || '<tr><td colspan="7" class="muted">No matching blocks.</td></tr>'}</tbody>
    </table>`;

    left.querySelectorAll('tbody tr[data-idx]').forEach((tr) => {
      tr.addEventListener('click', () => {
        const idx = Number(tr.dataset.idx);
        state.selected = idx;
        left.querySelectorAll('tbody tr').forEach((row) => row.classList.toggle('sel', Number(row.dataset.idx) === idx));
        post({ type: 'detail', index: idx });
      });
    });

    const pages = Math.max(1, Math.ceil(state.total / state.pageSize));
    document.getElementById('pageInfo').textContent = `Page ${state.page + 1} of ${pages} (${state.total} blocks)`;
    document.getElementById('prev').disabled = state.page <= 0;
    document.getElementById('next').disabled = (state.page + 1) * state.pageSize >= state.total;
  }

  function renderDetail(d) {
    const el = document.getElementById('detail');
    if (!d) {
      el.innerHTML = '<p class="muted">No block selected.</p>';
      return;
    }
    const pairs = [
      ['Lines', `${d.line}-${d.endLine}`],
      ['Kind', d.kind],
      ['Address', d.address],
      ['DAG Tier', `Tier ${d.depth}`],
      ['Type / Source', d.source || d.type],
      ['Version', d.version || '(unset)'],
      ['References', d.refs.length ? d.refs.join(', ') : '(none)'],
      ['Status', d.status.toUpperCase()],
    ];
    const rows = pairs.map(([k, v]) => `<tr><td><strong>${esc(k)}</strong></td><td><code>${esc(v)}</code></td></tr>`).join('');
    const fItems = (d.findings || []).map((f) => `<li class="${f.severity === 'error' ? 'bad' : ''}"><strong>[${esc(f.severity.toUpperCase())}] ${esc(f.rule)}:</strong> ${esc(f.message)}</li>`).join('');
    const attrRows = (d.attrs || []).slice(0, 40).map((a) => `<tr><td class="num">${a.line}</td><td><code>${esc(a.key)}</code></td><td><code>${esc(a.value)}</code></td></tr>`).join('');

    el.innerHTML = `
      <div class="dhead"><strong>Line ${d.line}: ${esc(d.address)}</strong><span class="muted">${esc(d.kind)}</span></div>
      <table class="splits"><thead><tr><th>Field</th><th>Value</th></tr></thead><tbody>${rows}</tbody></table>
      ${fItems ? `<div class="attr-head"><strong>Findings (${d.findings.length})</strong></div><ul class="findings-list">${fItems}</ul>` : ''}
      <div class="attr-head"><strong>Attributes (${(d.attrs || []).length})</strong></div>
      <table class="splits"><thead><tr><th class="num">Line</th><th>Attribute</th><th>Value</th></tr></thead><tbody>${attrRows || '<tr><td colspan="3" class="muted">No attributes.</td></tr>'}</tbody></table>
    `;
  }

  window.addEventListener('message', (ev) => {
    const m = ev.data;
    if (!m || typeof m !== 'object') return;
    switch (m.type) {
      case 'init':
        if (m.error) {
          app.innerHTML = `<div class="error"><strong>Could not open ${esc(m.name)}</strong><p>${esc(m.error)}</p></div>`;
          return;
        }
        state.name = m.name;
        state.summary = m.summary;
        state.pageSize = m.pageSize || 100;
        state.page = 0;
        renderShell();
        loadPage();
        return;
      case 'pageResult':
        state.total = m.total;
        state.rows = m.rows || [];
        renderPane();
        if (state.rows.length && state.selected == null) {
          state.selected = state.rows[0].index;
          post({ type: 'detail', index: state.selected });
        }
        return;
      case 'filterResult':
        state.total = m.count;
        document.getElementById('hint').textContent = m.count < m.total ? `Showing ${m.count} of ${m.total} blocks.` : '';
        loadPage();
        return;
      case 'detailResult':
        renderDetail(m.detail);
        return;
      case 'zovoAlso': {
        const anchor = m.anchor && document.getElementById(m.anchor);
        if (anchor && m.html) {
          const old = document.querySelector('.zovo-also');
          if (old) old.remove();
          anchor.insertAdjacentHTML('afterend', m.html);
        }
        return;
      }
      case 'hint':
        if (document.getElementById('hint')) document.getElementById('hint').textContent = m.text || '';
        return;
      default:
    }
  });

  post({ type: 'ready' });
})();
