# Harness capabilities

Airgap Agent is a **secure-by-default, offline** agent harness — not a hosted agent platform.

## Runtime surfaces

| Surface | Command / endpoint | Use case |
|---------|-------------------|----------|
| One-shot CLI | `airgap-agent run "task"` | Scripts, batch jobs |
| Interactive CLI | `airgap-agent chat` | Multi-turn local sessions |
| Loopback API | `airgap-agent serve` | Integrations on `127.0.0.1` |
| Health | `GET /health` | Readiness checks |
| Metrics | `GET /metrics` | Prometheus text (optional) |
| Eval | `airgap-agent eval eval/fixtures` | Regression cases |
| Canaries | `airgap-agent canary` | Parser/security smoke tests |

## Tools (allowlisted)

| Tool | Capability | Default |
|------|------------|---------|
| `read_file` | `fs.read` | on |
| `list_directory` | `fs.list` | on |
| `search_text` | `fs.search` | on |
| `run_python` | `py.exec` | on |
| `write_file` | `fs.write` | **off** — add to `security.allowed_tools` and `allowed_capabilities` |

## Sessions (API)

1. `POST /v1/sessions` → `{ "session_id": "..." }`
2. `POST /v1/agent/run` with `{ "task": "...", "session_id": "..." }`

Sessions are in-memory, bounded, and loopback-only.

## Structured output

Set `agent.response_format: json` to require a final JSON object from the model.

## Chat templates (llama.cpp)

Set `inference.chat_template` to `generic`, `chatml`, `llama3`, or `mistral` for better tool-call formatting with local GGUF models.

## Enabling writes (opt-in)

```yaml
security:
  allowed_tools:
    - read_file
    - list_directory
    - search_text
    - run_python
    - write_file
  allowed_capabilities:
    - fs.read
    - fs.list
    - fs.search
    - fs.write
    - py.exec
```

Use `policies/write-enabled.example.yaml` as a signed policy reference.
