'use strict';
// Offline Terraform HCL2, .tfvars and .terraform.lock.hcl parser, dependency resolver and static security analyzer.
// Zero Terraform CLI calls, zero cloud APIs, plain JavaScript.

const SECRET_KEY_RE = /(password|passwd|secret|token|api_key|apikey|access_key|private_key|db_pass|master_password|client_secret)/i;
const AWS_KEY_RE = /\b(AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16})\b/;
const SENSITIVE_VALUE_RE = /(ghp_[A-Za-z0-9]{20,}|sk_live_[A-Za-z0-9]{16,}|AIza[0-9A-Za-z_-]{30,}|-----BEGIN (?:RSA |EC )?PRIVATE KEY-----)/;

function stripInlineComment(line) {
  let inQuote = false;
  let escape = false;
  for (let i = 0; i < line.length; i += 1) {
    const ch = line[i];
    if (escape) { escape = false; continue; }
    if (ch === '\\' && inQuote) { escape = true; continue; }
    if (ch === '"') { inQuote = !inQuote; continue; }
    if (!inQuote) {
      if (ch === '#') return line.slice(0, i);
      if (ch === '/' && line[i + 1] === '/') return line.slice(0, i);
    }
  }
  return line;
}

function countBraces(str) {
  let delta = 0;
  let inQuote = false;
  let escape = false;
  for (let i = 0; i < str.length; i += 1) {
    const ch = str[i];
    if (escape) { escape = false; continue; }
    if (ch === '\\' && inQuote) { escape = true; continue; }
    if (ch === '"') { inQuote = !inQuote; continue; }
    if (!inQuote) {
      if (ch === '{') delta += 1;
      else if (ch === '}') delta -= 1;
    }
  }
  return delta;
}

function unquote(v) {
  const s = String(v || '').trim();
  if ((s.startsWith('"') && s.endsWith('"')) || (s.startsWith("'") && s.endsWith("'"))) {
    return s.slice(1, -1);
  }
  return s;
}

function isSensitiveKey(key) {
  return SECRET_KEY_RE.test(String(key || ''));
}

function maskValue(key, val) {
  if (isSensitiveKey(key) || AWS_KEY_RE.test(String(val)) || SENSITIVE_VALUE_RE.test(String(val))) {
    return '***REDACTED***';
  }
  return String(val);
}

function detectFileKind(fileName) {
  const base = String(fileName || '').toLowerCase();
  if (base.endsWith('.terraform.lock.hcl') || base.endsWith('lock.hcl')) return 'lock';
  if (base.endsWith('.tfvars') || base.endsWith('.tfvars.json')) return 'tfvars';
  return 'tf';
}

function parseBlockHeader(trimmed) {
  // Matches: resource "aws_s3_bucket" "logs" { | module "vpc" { | provider "aws" { | variable "env" { | terraform { | locals {
  const m = trimmed.match(/^(resource|data|module|variable|output|provider|terraform|locals)\b(.*)\{\s*$/);
  if (!m) return null;
  const kind = m[1];
  const rest = m[2].trim();
  const labels = [];
  const re = /"([^"]*)"/g;
  let lm;
  while ((lm = re.exec(rest)) !== null) labels.push(lm[1]);
  return { kind, labels };
}

function extractAttributes(bodyLines) {
  const attrs = {};
  const attrList = [];
  let inHeredoc = null;
  for (const item of bodyLines) {
    const raw = item.text;
    const trimmed = raw.trim();
    if (inHeredoc) {
      if (trimmed === inHeredoc) inHeredoc = null;
      continue;
    }
    const clean = stripInlineComment(raw).trim();
    if (!clean || clean.startsWith('/*') || clean.startsWith('*')) continue;
    const hd = clean.match(/<<-?([A-Za-z_][A-Za-z0-9_]*)\s*$/);
    if (hd) {
      const eq = clean.match(/^([A-Za-z_][A-Za-z0-9_-]*)\s*=\s*(.+)$/);
      if (eq) {
        attrs[eq[1]] = eq[2].trim();
        attrList.push({ line: item.line, key: eq[1], value: eq[2].trim() });
      }
      inHeredoc = hd[1];
      continue;
    }
    const eq = clean.match(/^([A-Za-z_][A-Za-z0-9_-]*)\s*=\s*(.+)$/);
    if (eq) {
      const key = eq[1];
      const val = eq[2].trim();
      if (!(key in attrs)) attrs[key] = val;
      attrList.push({ line: item.line, key, value: val });
    }
  }
  return { attrs, attrList };
}

function extractRefs(bodyText, selfAddr, knownAddrs) {
  const refs = new Set();
  const patterns = [
    /\b(var\.[A-Za-z_][A-Za-z0-9_-]*)\b/g,
    /\b(local\.[A-Za-z_][A-Za-z0-9_-]*)\b/g,
    /\b(module\.[A-Za-z_][A-Za-z0-9_-]*)\b/g,
    /\b(data\.[A-Za-z_][A-Za-z0-9_-]*\.[A-Za-z_][A-Za-z0-9_-]*)\b/g,
    /\b([a-z][a-z0-9_]*_[a-z0-9_]+\.[A-Za-z_][A-Za-z0-9_-]*)\b/g,
  ];
  for (const re of patterns) {
    let m;
    while ((m = re.exec(bodyText)) !== null) {
      const ref = m[1];
      if (ref === selfAddr) continue;
      if (ref.startsWith('var.') || ref.startsWith('local.') || ref.startsWith('module.') || ref.startsWith('data.') || knownAddrs.has(ref)) {
        refs.add(ref);
      }
    }
  }
  return [...refs].sort();
}

function isRemoteModuleSource(src) {
  const s = unquote(src);
  if (!s) return false;
  if (s.startsWith('./') || s.startsWith('../') || s.startsWith('/')) return false;
  return true;
}

function parseTerraform(input, fileName = 'main.tf') {
  const text = Buffer.isBuffer(input) ? input.toString('utf8') : String(input || '');
  const lines = text.split(/\r?\n/);
  const fileKind = detectFileKind(fileName);
  const blocks = [];
  const tfvars = [];
  const providers = [];
  const modules = [];
  const findings = [];

  if (fileKind === 'tfvars') {
    let depth = 0;
    let inMultiComment = false;
    for (let i = 0; i < lines.length; i += 1) {
      const lineNo = i + 1;
      const raw = lines[i];
      if (inMultiComment) {
        if (raw.includes('*/')) inMultiComment = false;
        continue;
      }
      if (raw.trim().startsWith('/*')) {
        if (!raw.includes('*/')) inMultiComment = true;
        continue;
      }
      const clean = stripInlineComment(raw).trim();
      if (!clean) continue;
      if (depth === 0) {
        const m = clean.match(/^([A-Za-z_][A-Za-z0-9_-]*)\s*=\s*(.+)$/);
        if (m) {
          const key = m[1];
          const val = m[2].trim();
          const sensitive = isSensitiveKey(key) || AWS_KEY_RE.test(val) || SENSITIVE_VALUE_RE.test(val);
          tfvars.push({
            index: tfvars.length + 1,
            line: lineNo,
            kind: 'tfvar',
            type: 'variable-value',
            name: key,
            address: `var.${key}`,
            source: '',
            version: '',
            value: val,
            displayValue: sensitive ? '***REDACTED***' : val,
            sensitive,
            refs: [],
            depth: 0,
            attrs: [{ line: lineNo, key, value: sensitive ? '***REDACTED***' : val }],
            findings: [],
          });
          if (sensitive && !/^["']?\$\{/.test(val) && unquote(val).length >= 4 && !/^(changeme|example|placeholder|null)$/i.test(unquote(val))) {
            const f = {
              severity: 'error',
              category: 'Secrets',
              rule: 'hardcoded-secret',
              line: lineNo,
              section: `var.${key}`,
              message: `Sensitive variable "${key}" has a hardcoded plaintext value in ${fileName}. Inject via TF_VAR_* or a secrets manager.`,
            };
            findings.push(f);
            tfvars[tfvars.length - 1].findings.push(f);
          }
        }
      }
      depth = Math.max(0, depth + countBraces(clean));
    }
    const rows = tfvars.map((v) => ({
      ...v,
      errorCount: v.findings.filter((f) => f.severity === 'error').length,
      warningCount: v.findings.filter((f) => f.severity === 'warning').length,
      status: v.findings.some((f) => f.severity === 'error') ? 'error' : (v.findings.length ? 'warning' : 'ok'),
    }));
    return {
      fileName,
      fileKind,
      totalLines: lines.length,
      rows,
      providers,
      modules,
      tfvars,
      findings,
      stats: {
        blockCount: rows.length,
        resourceCount: 0,
        dataCount: 0,
        moduleCount: 0,
        variableCount: rows.length,
        outputCount: 0,
        providerCount: 0,
        unpinnedCount: 0,
        errorCount: findings.filter((f) => f.severity === 'error').length,
        warningCount: findings.filter((f) => f.severity === 'warning').length,
      },
    };
  }

  // Parse HCL2 blocks (.tf or .terraform.lock.hcl)
  let current = null;
  let braceDepth = 0;
  let inMultiComment = false;
  let inHeredoc = null;

  for (let i = 0; i < lines.length; i += 1) {
    const lineNo = i + 1;
    const raw = lines[i];
    if (inHeredoc) {
      if (current) current.bodyLines.push({ line: lineNo, text: raw });
      if (raw.trim() === inHeredoc) inHeredoc = null;
      continue;
    }
    if (inMultiComment) {
      if (raw.includes('*/')) inMultiComment = false;
      continue;
    }
    const trimmed = raw.trim();
    if (trimmed.startsWith('/*')) {
      if (!trimmed.includes('*/')) inMultiComment = true;
      continue;
    }
    const clean = stripInlineComment(raw).trim();
    if (!clean) continue;

    if (!current) {
      const hdr = parseBlockHeader(clean);
      if (hdr) {
        current = {
          kind: hdr.kind,
          labels: hdr.labels,
          line: lineNo,
          endLine: lineNo,
          bodyLines: [],
        };
        braceDepth = countBraces(clean);
        if (braceDepth <= 0) {
          blocks.push(current);
          current = null;
          braceDepth = 0;
        }
      }
      continue;
    }

    current.bodyLines.push({ line: lineNo, text: raw });
    const hd = clean.match(/<<-?([A-Za-z_][A-Za-z0-9_]*)\s*$/);
    if (hd) {
      inHeredoc = hd[1];
      continue;
    }
    braceDepth += countBraces(clean);
    if (braceDepth <= 0) {
      current.endLine = lineNo;
      blocks.push(current);
      current = null;
      braceDepth = 0;
    }
  }
  if (current) {
    current.endLine = lines.length;
    blocks.push(current);
  }

  // Build normalized rows
  const rawRows = blocks.map((b, idx) => {
    const { attrs, attrList } = extractAttributes(b.bodyLines);
    const bodyText = b.bodyLines.map((l) => l.text).join('\n');
    let type = b.kind;
    let name = b.labels[0] || b.kind;
    let address = b.kind;
    if (b.kind === 'resource') {
      type = b.labels[0] || 'resource';
      name = b.labels[1] || `res_${idx + 1}`;
      address = `${type}.${name}`;
    } else if (b.kind === 'data') {
      type = b.labels[0] || 'data';
      name = b.labels[1] || `data_${idx + 1}`;
      address = `data.${type}.${name}`;
    } else if (b.kind === 'module') {
      type = 'module';
      name = b.labels[0] || `mod_${idx + 1}`;
      address = `module.${name}`;
    } else if (b.kind === 'variable') {
      type = unquote(attrs.type || 'any');
      name = b.labels[0] || `var_${idx + 1}`;
      address = `var.${name}`;
    } else if (b.kind === 'output') {
      type = 'output';
      name = b.labels[0] || `out_${idx + 1}`;
      address = `output.${name}`;
    } else if (b.kind === 'provider') {
      type = 'provider';
      name = b.labels[0] || 'provider';
      address = `provider.${name}`;
    } else if (b.kind === 'locals') {
      type = 'locals';
      name = `locals_${b.line}`;
      address = `locals@${b.line}`;
    } else if (b.kind === 'terraform') {
      type = 'terraform';
      name = 'settings';
      address = 'terraform';
    }

    const source = attrs.source ? unquote(attrs.source) : (b.kind === 'provider' && fileKind === 'lock' ? name : '');
    const version = attrs.version ? unquote(attrs.version) : (attrs.constraints ? unquote(attrs.constraints) : (attrs.required_version ? unquote(attrs.required_version) : ''));

    return {
      index: idx + 1,
      line: b.line,
      endLine: b.endLine,
      kind: b.kind,
      type,
      name,
      address,
      source,
      version,
      attrsMap: attrs,
      attrs: attrList.map((a) => ({ line: a.line, key: a.key, value: maskValue(a.key, a.value) })),
      rawAttrs: attrList,
      bodyLines: b.bodyLines,
      bodyText,
      refs: [],
      depth: 0,
      findings: [],
    };
  });

  const knownAddrs = new Set(rawRows.map((r) => r.address));

  // Extract provider & module entries, dependency references, and static security findings
  for (const r of rawRows) {
    r.refs = extractRefs(r.bodyText, r.address, knownAddrs);

    if (r.kind === 'module') {
      const remote = isRemoteModuleSource(r.source);
      const pinned = Boolean(r.version) || /[?&]ref=([0-9a-f]{40}|v?\d+\.\d+)/i.test(r.source);
      modules.push({
        line: r.line,
        name: r.name,
        source: r.source || '(missing)',
        version: r.version || (remote ? '(unpinned)' : '(local)'),
        pinned: !remote || pinned,
        status: !remote || pinned ? 'ok' : 'warning',
      });
      if (remote && !pinned) {
        const f = {
          severity: 'warning',
          category: 'Supply Chain',
          rule: 'unpinned-module',
          line: r.line,
          section: r.address,
          message: `Remote module "${r.name}" (${r.source}) has no version constraint or ref pin.`,
        };
        findings.push(f);
        r.findings.push(f);
      }
    }

    if (r.kind === 'provider') {
      const pinned = Boolean(r.version);
      providers.push({
        line: r.line,
        name: r.name,
        source: r.source || r.name,
        version: r.version || (fileKind === 'lock' ? '(locked)' : '(inherited)'),
        pinned: fileKind === 'lock' ? Boolean(r.version) : true,
        status: 'ok',
      });
    }

    if (r.kind === 'terraform') {
      // Scan required_providers inner entries
      let curProv = null;
      for (const bl of r.bodyLines) {
        const cl = stripInlineComment(bl.text).trim();
        const pm = cl.match(/^([A-Za-z0-9_-]+)\s*=\s*\{/);
        if (pm && pm[1] !== 'required_providers') {
          curProv = { line: bl.line, name: pm[1], source: '', version: '' };
          providers.push(curProv);
        } else if (curProv) {
          const sm = cl.match(/^source\s*=\s*"([^"]+)"/);
          const vm = cl.match(/^version\s*=\s*"([^"]+)"/);
          if (sm) curProv.source = sm[1];
          if (vm) curProv.version = vm[1];
          if (cl === '}') {
            curProv.pinned = Boolean(curProv.version);
            curProv.status = curProv.pinned ? 'ok' : 'warning';
            if (!curProv.pinned) {
              const f = {
                severity: 'warning',
                category: 'Supply Chain',
                rule: 'unpinned-provider',
                line: curProv.line,
                section: `terraform.required_providers.${curProv.name}`,
                message: `Provider "${curProv.name}" has no version constraint in required_providers.`,
              };
              findings.push(f);
              r.findings.push(f);
            }
            curProv = null;
          }
        }
      }
    }

    // Static security checks on block body lines
    const isSgOrFw = /(security_group|firewall|network_acl|ingress)/i.test(r.type) || /\bingress\s*\{/i.test(r.bodyText);
    for (const bl of r.bodyLines) {
      const cl = stripInlineComment(bl.text);
      if (!cl.trim()) continue;

      if (isSgOrFw && /(?:0\.0\.0\.0\/0|::\/0)/.test(cl) && !/egress/i.test(cl)) {
        const f = {
          severity: 'error',
          category: 'Network',
          rule: 'open-ingress',
          line: bl.line,
          section: r.address,
          message: `Open ingress CIDR (0.0.0.0/0 or ::/0) in ${r.address} exposes ports to the public internet.`,
        };
        findings.push(f);
        r.findings.push(f);
      }

      if (/\b(?:encrypted|storage_encrypted|kms_key_id_enabled|enable_encryption)\s*=\s*false\b/i.test(cl)) {
        const f = {
          severity: 'error',
          category: 'Encryption',
          rule: 'unencrypted-storage',
          line: bl.line,
          section: r.address,
          message: `Storage encryption is explicitly disabled in ${r.address}. Set encrypted / storage_encrypted = true.`,
        };
        findings.push(f);
        r.findings.push(f);
      }

      if (/\b(acl\s*=\s*"public-read[^"]*"|publicly_accessible\s*=\s*true|block_public_acls\s*=\s*false)\b/i.test(cl)) {
        const f = {
          severity: 'warning',
          category: 'Exposure',
          rule: 'public-access',
          line: bl.line,
          section: r.address,
          message: `Public access enabled in ${r.address}: ${cl.trim().slice(0, 80)}.`,
        };
        findings.push(f);
        r.findings.push(f);
      }

      if (/"Action"\s*:\s*"\*"|actions\s*=\s*\[\s*"\*"\s*\]/.test(cl)) {
        const f = {
          severity: 'error',
          category: 'IAM',
          rule: 'wildcard-iam',
          line: bl.line,
          section: r.address,
          message: `Wildcard IAM Action ("*") found in ${r.address}. Scope permissions to least privilege.`,
        };
        findings.push(f);
        r.findings.push(f);
      }

      if (AWS_KEY_RE.test(cl) || SENSITIVE_VALUE_RE.test(cl)) {
        const f = {
          severity: 'error',
          category: 'Secrets',
          rule: 'hardcoded-secret',
          line: bl.line,
          section: r.address,
          message: `Hardcoded credential or key literal detected in ${r.address}.`,
        };
        findings.push(f);
        r.findings.push(f);
      } else {
        const kv = cl.trim().match(/^([A-Za-z_][A-Za-z0-9_-]*)\s*=\s*"([^"]+)"/);
        if (kv && isSensitiveKey(kv[1]) && !kv[2].includes('${') && kv[2].length >= 6 && !/^(changeme|example|placeholder)$/i.test(kv[2])) {
          const f = {
            severity: 'error',
            category: 'Secrets',
            rule: 'hardcoded-secret',
            line: bl.line,
            section: r.address,
            message: `Hardcoded secret attribute "${kv[1]}" in ${r.address}. Use a variable or secrets manager reference.`,
          };
          findings.push(f);
          r.findings.push(f);
        }
      }
    }
  }

  // Compute DAG depth tiers
  const byAddr = new Map(rawRows.map((r) => [r.address, r]));
  const memo = new Map();
  function depthOf(addr, stack) {
    if (memo.has(addr)) return memo.get(addr);
    if (stack.has(addr)) return 0;
    const node = byAddr.get(addr);
    if (!node || !node.refs.length) {
      memo.set(addr, 0);
      return 0;
    }
    stack.add(addr);
    let maxParent = -1;
    for (const ref of node.refs) {
      if (byAddr.has(ref)) {
        maxParent = Math.max(maxParent, depthOf(ref, stack));
      }
    }
    stack.delete(addr);
    const d = maxParent + 1;
    memo.set(addr, d);
    return d;
  }
  for (const r of rawRows) r.depth = depthOf(r.address, new Set());

  const rows = rawRows.map((r) => {
    const errorCount = r.findings.filter((f) => f.severity === 'error').length;
    const warningCount = r.findings.filter((f) => f.severity === 'warning').length;
    return {
      index: r.index,
      line: r.line,
      endLine: r.endLine,
      kind: r.kind,
      type: r.type,
      name: r.name,
      address: r.address,
      source: r.source,
      version: r.version,
      depth: r.depth,
      refs: r.refs,
      attrs: r.attrs,
      findings: r.findings,
      errorCount,
      warningCount,
      status: errorCount > 0 ? 'error' : (warningCount > 0 ? 'warning' : 'ok'),
    };
  });

  return {
    fileName,
    fileKind,
    totalLines: lines.length,
    rows,
    providers,
    modules,
    tfvars,
    findings,
    stats: {
      blockCount: rows.length,
      resourceCount: rows.filter((r) => r.kind === 'resource').length,
      dataCount: rows.filter((r) => r.kind === 'data').length,
      moduleCount: rows.filter((r) => r.kind === 'module').length,
      variableCount: rows.filter((r) => r.kind === 'variable').length,
      outputCount: rows.filter((r) => r.kind === 'output').length,
      providerCount: providers.length,
      unpinnedCount: modules.filter((m) => !m.pinned).length + providers.filter((p) => !p.pinned).length,
      errorCount: findings.filter((f) => f.severity === 'error').length,
      warningCount: findings.filter((f) => f.severity === 'warning').length,
    },
  };
}

function safeId(s) {
  return String(s || 'node').replace(/[^A-Za-z0-9_]/g, '_');
}

function buildMermaidGraph(parsed) {
  const lines = ['flowchart LR'];
  const known = new Set(parsed.rows.map((r) => r.address));
  for (const r of parsed.rows) {
    lines.push(`  ${safeId(r.address)}["${r.address.replace(/"/g, "'")}"]`);
  }
  for (const r of parsed.rows) {
    for (const ref of r.refs) {
      if (known.has(ref)) {
        lines.push(`  ${safeId(ref)} --> ${safeId(r.address)}`);
      }
    }
  }
  return lines.join('\n');
}

function buildAuditMarkdown(entries) {
  const out = ['# Terraform HCL Security & Module-Pinning Audit', ''];
  let totalErrors = 0;
  let totalWarnings = 0;
  for (const e of entries) {
    totalErrors += e.parsed.stats.errorCount;
    totalWarnings += e.parsed.stats.warningCount;
  }
  out.push(`- Files audited: **${entries.length}**`);
  out.push(`- Errors: **${totalErrors}** | Warnings: **${totalWarnings}**`, '');
  for (const e of entries) {
    const p = e.parsed;
    out.push(`## ${e.fileName}`);
    out.push(`Blocks: ${p.stats.blockCount} | Resources: ${p.stats.resourceCount} | Modules: ${p.stats.moduleCount} | Providers: ${p.stats.providerCount} | Unpinned: ${p.stats.unpinnedCount}`, '');
    if (p.findings.length === 0) {
      out.push('No static security or pinning findings.', '');
    } else {
      out.push('| Severity | Category | Rule | Line | Scope | Finding |');
      out.push('| --- | --- | --- | ---: | --- | --- |');
      for (const f of p.findings) {
        out.push(`| ${f.severity.toUpperCase()} | ${f.category} | \`${f.rule}\` | ${f.line} | \`${f.section}\` | ${f.message.replace(/\|/g, '\\|')} |`);
      }
      out.push('');
    }
  }
  return out.join('\n');
}

function buildDiffMarkdown(leftName, left, rightName, right) {
  const out = [
    '# Terraform HCL & Variable Comparison Report',
    '',
    `- Baseline: \`${leftName}\` (${left.stats.blockCount} entries, ${left.stats.errorCount} errors, ${left.stats.warningCount} warnings)`,
    `- Target: \`${rightName}\` (${right.stats.blockCount} entries, ${right.stats.errorCount} errors, ${right.stats.warningCount} warnings)`,
    '',
  ];
  const lMap = new Map(left.rows.map((r) => [r.address, r]));
  const rMap = new Map(right.rows.map((r) => [r.address, r]));
  const allKeys = [...new Set([...lMap.keys(), ...rMap.keys()])].sort();
  out.push('## Block & Variable Diff (Secrets Masked)', '');
  out.push('| Address | Change | Baseline | Target |');
  out.push('| --- | --- | --- | --- |');
  let changes = 0;
  for (const k of allKeys) {
    const a = lMap.get(k);
    const b = rMap.get(k);
    if (!a && b) {
      changes += 1;
      out.push(`| \`${k}\` | ADDED | — | \`${b.displayValue || b.version || b.type}\` |`);
    } else if (a && !b) {
      changes += 1;
      out.push(`| \`${k}\` | REMOVED | \`${a.displayValue || a.version || a.type}\` | — |`);
    } else if (a && b) {
      const av = a.displayValue || a.version || a.source || a.status;
      const bv = b.displayValue || b.version || b.source || b.status;
      if (av !== bv) {
        changes += 1;
        out.push(`| \`${k}\` | CHANGED | \`${av}\` | \`${bv}\` |`);
      }
    }
  }
  if (!changes) out.push('| (none) | UNCHANGED | — | — |');
  out.push('', '## Security Finding Delta', '');
  const lRules = new Set(left.findings.map((f) => `${f.rule}@${f.section}`));
  const rRules = new Set(right.findings.map((f) => `${f.rule}@${f.section}`));
  const resolved = [...lRules].filter((x) => !rRules.has(x));
  const introduced = [...rRules].filter((x) => !lRules.has(x));
  out.push(`- RESOLVED: ${resolved.length ? resolved.map((x) => `\`${x}\``).join(', ') : 'none'}`);
  out.push(`- INTRODUCED: ${introduced.length ? introduced.map((x) => `\`${x}\``).join(', ') : 'none'}`, '');
  return out.join('\n');
}

function csvCell(v) {
  const s = String(v == null ? '' : v);
  return /[",\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

function buildInventoryCsv(parsed) {
  const lines = ['kind,line,address,type,source,version,depth,refs,status'];
  for (const r of parsed.rows) {
    lines.push([
      r.kind,
      r.line,
      r.address,
      r.type,
      r.source,
      r.version,
      r.depth,
      r.refs.join('; '),
      r.status,
    ].map(csvCell).join(','));
  }
  return lines.join('\n') + '\n';
}

function buildReportMarkdown(parsed, fileName) {
  const out = [
    `# Terraform HCL Inventory Report: ${fileName}`,
    '',
    `- Blocks: **${parsed.stats.blockCount}** (Resources: ${parsed.stats.resourceCount}, Data: ${parsed.stats.dataCount}, Modules: ${parsed.stats.moduleCount}, Variables: ${parsed.stats.variableCount}, Outputs: ${parsed.stats.outputCount})`,
    `- Providers: **${parsed.stats.providerCount}** | Unpinned: **${parsed.stats.unpinnedCount}** | Findings: **${parsed.stats.errorCount} errors, ${parsed.stats.warningCount} warnings**`,
    '',
    '## Dependency Graph',
    '',
    '```mermaid',
    buildMermaidGraph(parsed),
    '```',
    '',
    '## Resource & Module Table',
    '',
    '| Line | Kind | Address | Source / Type | Version | Tier | Status |',
    '| ---: | --- | --- | --- | --- | ---: | --- |',
  ];
  for (const r of parsed.rows) {
    out.push(`| ${r.line} | ${r.kind} | \`${r.address}\` | \`${r.source || r.type}\` | \`${r.version || '-'}\` | T${r.depth} | ${r.status.toUpperCase()} |`);
  }
  out.push('');
  return out.join('\n');
}

module.exports = {
  parseTerraform,
  buildMermaidGraph,
  buildAuditMarkdown,
  buildDiffMarkdown,
  buildInventoryCsv,
  buildReportMarkdown,
  maskValue,
};
