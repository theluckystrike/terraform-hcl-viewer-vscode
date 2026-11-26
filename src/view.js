'use strict';
// View model for Terraform HCL & Module Viewer: pagination, search/filter, providers, modules and findings.

class TerraformViewModel {
  constructor(parsed, name, fileSize) {
    this.parsed = parsed;
    this.name = name;
    this.fileSize = fileSize;
    this.filter = { text: '', status: '' };
    this.filtered = parsed.rows.slice();
  }

  summary() {
    const p = this.parsed;
    const s = p.stats;
    return {
      name: this.name,
      fileKind: p.fileKind,
      fileSize: this.fileSize,
      totalLines: p.totalLines,
      blockCount: s.blockCount,
      resourceCount: s.resourceCount,
      dataCount: s.dataCount,
      moduleCount: s.moduleCount,
      variableCount: s.variableCount,
      outputCount: s.outputCount,
      providerCount: s.providerCount,
      unpinnedCount: s.unpinnedCount,
      errorCount: s.errorCount,
      warningCount: s.warningCount,
      providers: p.providers,
      modules: p.modules,
      findings: p.findings,
    };
  }

  totalCount() {
    return this.parsed.rows.length;
  }

  count() {
    return this.filtered.length;
  }

  setFilter(f) {
    const text = f && typeof f.text === 'string' ? f.text.trim().toLowerCase() : '';
    const status = f && typeof f.status === 'string' ? f.status.trim() : '';
    this.filter = { text, status };
    this.filtered = this.parsed.rows.filter((r) => {
      if (status === 'error' && r.status !== 'error') return false;
      if (status === 'warning' && r.status !== 'warning') return false;
      if (status === 'ok' && r.status !== 'ok') return false;
      if (status === 'resource' && r.kind !== 'resource') return false;
      if (status === 'module' && r.kind !== 'module') return false;
      if (status === 'variable' && r.kind !== 'variable' && r.kind !== 'tfvar') return false;
      if (text) {
        const hay = `${r.kind} ${r.address} ${r.type} ${r.name} ${r.source} ${r.version} ${r.refs.join(' ')}`.toLowerCase();
        if (!hay.includes(text)) return false;
      }
      return true;
    });
    return this.filtered.length;
  }

  rows(from, limit) {
    const start = Math.max(0, Number(from) || 0);
    const n = Math.max(1, Math.min(500, Number(limit) || 100));
    return this.filtered.slice(start, start + n).map((r) => ({
      index: r.index,
      line: r.line,
      kind: r.kind,
      address: r.address,
      type: r.type,
      source: r.source,
      version: r.version,
      depth: r.depth,
      refCount: r.refs.length,
      errorCount: r.errorCount,
      warningCount: r.warningCount,
      status: r.status,
    }));
  }

  detail(index) {
    const r = this.parsed.rows.find((x) => x.index === index) || this.parsed.rows[0] || null;
    if (!r) return null;
    return {
      index: r.index,
      line: r.line,
      endLine: r.endLine || r.line,
      kind: r.kind,
      address: r.address,
      type: r.type,
      name: r.name,
      source: r.source,
      version: r.version,
      depth: r.depth,
      refs: r.refs,
      status: r.status,
      findings: r.findings,
      attrs: r.attrs,
    };
  }
}

module.exports = { TerraformViewModel };
