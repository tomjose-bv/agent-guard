# Changelog

All notable changes to this project are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-10-18

First public release.

### Added

- MCP proxy that sits between an AI agent and its MCP servers, configured in YAML.
- Policies: allow/deny tool globs, argument constraints, rate limits and spend limits.
- PII detection (emails, phone numbers, card numbers with Luhn check, IBANs with
  checksum) with redact, block and log-only modes.
- `require_approval` action with CLI approve/deny and timeout-to-deny.
- Hash-chained JSONL audit log with `verify-log` and `log` commands.
- Local web viewer for the audit log and pending approvals.
- Scripted demo agent and an optional OpenAI-compatible LLM agent.
- Latency benchmark (the audit log keeps its file handle open).
- One-command setup scripts, example policies and GitHub Actions CI on Ubuntu and
  Windows with Python 3.10–3.12.

[0.1.0]: https://github.com/tomjose-bv/agent-guard/releases/tag/v0.1.0
