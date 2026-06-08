# Changelog

All notable changes to this project will be documented in this file.

## Unreleased

- Bump dependency lower bounds: cryptography, httpx, pydantic, pydantic-settings, structlog, typer, rich, llama-cpp-python, huggingface_hub, pytest-asyncio, and ruff.
- Fix license metadata to match GPL-3.0 (LICENSE + README).
- Harden loopback API: startup secret validation, constant-time Bearer auth, 403 vs 401, safe JSON parsing, dev-mode auth parity.
- Add fs.list/fs.search path-scoped policy enforcement; harden search_text with os.walk (no symlink follow).
- Wire tool_denials Prometheus metric; expose budget_denials in run/API responses.
- Thread-safe llama.cpp inference; validate OpenAI-compat responses.
- Add GET/DELETE session endpoints; `--json` flag on `run`.
- Add CI workflow, serve API tests, and CODE_OF_CONDUCT.md.
- Add Hugging Face Hub staging downloader (`airgap-agent hf-download`) and provenance metadata (`HF_SOURCE.json`).
- Add signed bundle + signed policy verification and hash-chained audit logs.
- Harden tool gate, sandbox, filesystem jail, and loopback API token auth.

