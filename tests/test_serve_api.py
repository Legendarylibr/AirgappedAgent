from __future__ import annotations

import threading
from http.server import HTTPServer
from pathlib import Path
from unittest.mock import patch

import pytest

from airgap_agent.agent import AgentHarness
from airgap_agent.agent.metrics import MetricsRegistry
from airgap_agent.agent.session import SessionStore
from airgap_agent.cli import _load
from airgap_agent.config import AuditSettings, TrustSettings
from airgap_agent.deployment.bootstrap import BootstrapError, validate_api_config
from airgap_agent.deployment.health import health_report
from airgap_agent.inference import create_backend
from airgap_agent.security import AuditLogger


def _dev_config(tmp_path: Path):
    ws = tmp_path / "workspace"
    ws.mkdir()
    (ws / "note.txt").write_text("hello from workspace")
    cfg = _load(None, dev=True)
    cfg.security.workspace_root = ws
    cfg.audit = AuditSettings(enabled=False)
    cfg.policy_path = Path("policies/default.yaml")
    cfg.trust = TrustSettings(require_signed_policy=False)
    return cfg


def test_validate_api_config_requires_token_when_enabled() -> None:
    cfg = _load(None, dev=False)
    cfg.api.require_token = True
    with patch.dict("os.environ", {}, clear=True):
        with pytest.raises(BootstrapError, match="AIRGAP_API_TOKEN"):
            validate_api_config(cfg)


def test_serve_handler_dev_health_and_run(tmp_path: Path) -> None:
    import http.server
    import json as jsonlib

    cfg = _dev_config(tmp_path)
    validate_api_config(cfg)
    backend = create_backend(cfg)
    from airgap_agent.security.policy import PolicyEngine

    policy = PolicyEngine(Path("policies/default.yaml"), cfg.trust)
    audit = AuditLogger(cfg.audit)
    metrics = MetricsRegistry()
    sessions = SessionStore(
        max_sessions=cfg.api.sessions.max_sessions,
        max_messages=cfg.api.sessions.max_messages_per_session,
        ttl_seconds=cfg.api.sessions.ttl_seconds,
    )

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: object) -> None:
            return

        def _headers_map(self) -> dict[str, str]:
            return {k: v for k, v in self.headers.items()}

        def _json(self, code: int, payload: dict) -> None:
            body = jsonlib.dumps(payload).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:
            if self.path == "/health":
                self._json(200, health_report(cfg, backend))

        def do_POST(self) -> None:
            if self.path == "/v1/sessions":
                sid = sessions.create()
                self._json(201, {"session_id": sid, "ttl_seconds": cfg.api.sessions.ttl_seconds})
                return
            if self.path != "/v1/agent/run":
                self._json(404, {"error": "not found"})
                return
            length = int(self.headers.get("Content-Length", 0))
            raw = self.rfile.read(length).decode()
            data = jsonlib.loads(raw)
            harness = AgentHarness(cfg, backend, policy, audit, metrics=metrics)
            result = harness.run(data["task"])
            self._json(
                200,
                {
                    "answer": result.answer,
                    "run_id": result.run_id,
                    "budget_denials": result.budget_denials,
                },
            )

    server = HTTPServer(("127.0.0.1", 0), Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    import httpx

    try:
        client = httpx.Client(base_url=f"http://127.0.0.1:{port}", timeout=30.0)
        health = client.get("/health")
        assert health.status_code == 200
        assert health.json()["status"] in ("ok", "degraded")

        run = client.post(
            "/v1/agent/run",
            json={"task": "List workspace files"},
        )
        assert run.status_code == 200
        body = run.json()
        assert body["answer"]
        assert "run_id" in body

        session = client.post("/v1/sessions")
        assert session.status_code == 201
        assert session.json()["session_id"]
    finally:
        server.shutdown()
        server.server_close()


def test_fs_list_and_search_policy(tmp_path: Path) -> None:
    from airgap_agent.security.policy import PolicyEngine

    engine = PolicyEngine(Path("policies/default.yaml"), TrustSettings(require_signed_policy=False))
    ws = tmp_path / "workspace"
    ws.mkdir()
    assert (
        engine.evaluate("fs.list", {"path": str(ws), "workspace_root": str(ws)}).effect == "allow"
    )
    assert (
        engine.evaluate("fs.search", {"path": str(ws), "workspace_root": str(ws)}).effect == "allow"
    )
