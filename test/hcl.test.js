'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const {
  parseTerraform,
  buildMermaidGraph,
  buildAuditMarkdown,
  buildDiffMarkdown,
  buildInventoryCsv,
  buildReportMarkdown,
} = require('../src/hcl');
const { TerraformViewModel } = require('../src/view');
const { editorHtml, csp } = require('../src/html');

test('parses sample main.tf with resources, modules, providers, dependencies and security findings', () => {
  const buf = fs.readFileSync(path.join(__dirname, '..', 'samples', 'main.tf'));
  const parsed = parseTerraform(buf, 'main.tf');
  assert.equal(parsed.stats.resourceCount, 2);
  assert.equal(parsed.stats.moduleCount, 1);
  assert.equal(parsed.stats.variableCount, 1);
  assert.equal(parsed.stats.outputCount, 1);
  assert.equal(parsed.stats.providerCount, 1);

  const rules = new Set(parsed.findings.map((f) => f.rule));
  assert.ok(rules.has('unpinned-module'));
  assert.ok(rules.has('open-ingress'));
  assert.ok(rules.has('unencrypted-storage'));
  assert.ok(rules.has('hardcoded-secret'));

  const outRow = parsed.rows.find((r) => r.address === 'output.db_endpoint');
  assert.ok(outRow && outRow.depth >= 2);
});

test('parses .tfvars with secret masking and hardcoded-secret detection', () => {
  const tfvars = [
    'environment = "prod"',
    'instance_count = 3',
    'db_password = "MyProdPassword123!"',
  ].join('\n');
  const parsed = parseTerraform(tfvars, 'prod.tfvars');
  assert.equal(parsed.fileKind, 'tfvars');
  assert.equal(parsed.rows.length, 3);
  const passRow = parsed.rows.find((r) => r.name === 'db_password');
  assert.equal(passRow.displayValue, '***REDACTED***');
  assert.ok(parsed.findings.some((f) => f.rule === 'hardcoded-secret'));
});

test('passes hardened Terraform file with zero findings', () => {
  const cleanTf = [
    'terraform {',
    '  required_providers {',
    '    aws = {',
    '      source  = "hashicorp/aws"',
    '      version = "~> 5.40"',
    '    }',
    '  }',
    '}',
    'module "vpc" {',
    '  source  = "terraform-aws-modules/vpc/aws"',
    '  version = "5.7.0"',
    '}',
    'resource "aws_db_instance" "clean" {',
    '  storage_encrypted = true',
    '}',
  ].join('\n');
  const parsed = parseTerraform(cleanTf, 'clean.tf');
  assert.equal(parsed.findings.length, 0);
  assert.equal(parsed.stats.unpinnedCount, 0);
});

test('TerraformViewModel filters by kind, error status and search text', () => {
  const buf = fs.readFileSync(path.join(__dirname, '..', 'samples', 'main.tf'));
  const parsed = parseTerraform(buf, 'main.tf');
  const vm = new TerraformViewModel(parsed, 'main.tf', buf.length);
  assert.equal(vm.totalCount(), 6);
  assert.equal(vm.setFilter({ text: '', status: 'resource' }), 2);
  assert.equal(vm.setFilter({ text: '', status: 'module' }), 1);
  assert.ok(vm.setFilter({ text: '', status: 'error' }) >= 2);
  assert.equal(vm.setFilter({ text: 'aws_db_instance', status: '' }), 1);
  const det = vm.detail(1);
  assert.ok(det && det.kind === 'terraform');
});

test('Pro report builders output Mermaid graph, audit, diff, CSV and report Markdown', () => {
  const buf = fs.readFileSync(path.join(__dirname, '..', 'samples', 'main.tf'));
  const left = parseTerraform(buf, 'staging.tfvars');
  const right = parseTerraform('environment = "prod"\ndb_password = "OtherSecretValue99"\n', 'prod.tfvars');
  const graph = buildMermaidGraph(parseTerraform(buf, 'main.tf'));
  assert.match(graph, /flowchart LR/);
  assert.match(graph, /aws_security_group_web --> aws_db_instance_primary/);
  const audit = buildAuditMarkdown([{ fileName: 'main.tf', parsed: parseTerraform(buf, 'main.tf') }]);
  assert.match(audit, /Terraform HCL Security & Module-Pinning Audit/);
  assert.match(audit, /open-ingress/);
  const diff = buildDiffMarkdown('staging.tfvars', left, 'prod.tfvars', right);
  assert.match(diff, /Terraform HCL & Variable Comparison Report/);
  assert.doesNotMatch(diff, /OtherSecretValue99/);
  const csv = buildInventoryCsv(parseTerraform(buf, 'main.tf'));
  assert.match(csv, /^kind,line,address,type,source,version,depth,refs,status/);
  const rep = buildReportMarkdown(parseTerraform(buf, 'main.tf'), 'main.tf');
  assert.match(rep, /```mermaid/);
});

test('editorHtml enforces strict CSP with nonce and no unsafe-inline', () => {
  const html = editorHtml({ cspSource: 'vscode-webview://test', script: 'v.js', styleUri: 'v.css', title: 'main.tf', nonce: 'tf123' });
  assert.match(html, /default-src 'none'/);
  assert.match(html, /script-src 'nonce-tf123'/);
  assert.doesNotMatch(csp('vscode-webview://test', 'tf123'), /unsafe-inline/);
});
