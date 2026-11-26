# Changelog

## 0.1.0

- First release: `*.tf`, `*.tfvars` and `.terraform.lock.hcl` in a read-only offline Terraform viewer, parsed locally with plain JavaScript and zero Terraform CLI or cloud calls.
- Resource, data, module, variable and output tree with dependency tiers, provider and module version table, and static security findings (`0.0.0.0/0` open ingress, unencrypted storage, hardcoded credentials, wildcard IAM and unpinned modules).
- Zovo Pro tools with 1 free try each: Markdown IaC security and module-pinning audit, two-file `.tfvars`/`.tf` Markdown diff with secrets masked, and Mermaid dependency graph plus Markdown and CSV resource inventory export. Get Zovo Pro first shows what Pro includes and the tries left, in an editor tab.
