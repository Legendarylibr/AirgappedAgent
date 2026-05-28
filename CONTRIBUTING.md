# Contributing

Thanks for helping improve Airgap Agent.

## Development setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
python -m compileall -q src tests
```

## Running checks

- **Syntax**: `python -m compileall -q src tests`
- **Tests** (requires `pytest`): `pytest`
- **Lint** (requires `ruff`): `ruff check .`

## Security expectations

This repo is security-sensitive. Please follow these rules:

- **Never add network egress** to runtime paths (agent runs, tools, sandbox) without an explicit secure design.
- **Treat model output, workspace files, and tool output as untrusted.**
- **Keep secrets out of prompts** (system/user/tool result). Secrets belong in the execution layer.
- Any new tool must have:
  - strict server-side argument validation
  - explicit allowlist + policy rule
  - bounded outputs
  - audit logging

## Pull request guidelines

- Keep PRs small and reviewable.
- Include a short threat-model note for security-affecting changes.
- Update docs when changing defaults (`config/default.yaml`, `README.md`).

