'use strict';
module.exports = {
  prefix: 'zovoTfHcl',
  triesKey: 'zovoTfHcl.proTrial',
  slot: '#protools',
  tools: [
    { id: 'auditSecurity', title: 'Audit Terraform HCL security and module pinning', command: 'zovoTfHcl.auditSecurity' },
    { id: 'diffVars', title: 'Compare two Terraform HCL or tfvars files', command: 'zovoTfHcl.diffVars' },
    { id: 'exportInventory', title: 'Export Mermaid dependency graph and resource inventory', command: 'zovoTfHcl.exportInventory' },
  ],
};
