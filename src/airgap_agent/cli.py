from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import structlog
import typer
from rich.console import Console
from rich.json import JSON
from rich.panel import Panel

from airgap_agent.agent import AgentHarness
from airgap_agent.config import AppConfig, BundleSettings, TrustSettings, load_config
from airgap_agent.crypto import generate_keypair, verify_audit_chain
from airgap_agent.crypto.encrypt import open_line, parse_key_material
from airgap_agent.deployment import (
    BootstrapError,
    ensure_runtime_ready,
    health_report,
    sign_manifest,
    validate_api_config,
    verify_capability_token_from_headers,
    verify_api_token,
    verify_bundle,
    write_manifest,
)
from airgap_agent.deployment.bundle import verify_signed_artifact
from airgap_agent.inference import create_backend
from airgap_agent.inference.base import ChatMessage
from airgap_agent.security import AuditLogger
from airgap_agent.agent.eval import load_eval_cases, run_eval_cases
from airgap_agent.agent.metrics import MetricsRegistry
from airgap_agent.agent.session import SessionStore
from airgap_agent.canaries import run_canaries

app = typer.Typer(
    name="airgap-agent",
    help="Airgapped, secure-by-default agentic AI harness for open-source models.",
    no_args_is_help=True,
)
console = Console()


def _setup_logging() -> None:
    structlog.configure(
        processors=[
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.add_log_level,
            structlog.dev.ConsoleRenderer(),
        ],
    )


def _load(path: Optional[Path], dev: bool) -> AppConfig:
    config = load_config(path)
    if dev:
        config.airgap.mode = "permissive"
        config.airgap.require_bundle_manifest = False
        config.trust.require_signed_manifest = False
        config.trust.require_signed_policy = False
        config.trust.public_keys_dir = Path("./trust")
        config.audit.log_path = Path("./.airgap/audit.jsonl")
        config.security.workspace_root = Path("./workspace")
        config.bundle.models_dir = Path("./models")
        config.api.require_token = False
        config.api.require_capability_token = False
        config.api.replay_protection = False
        config.api.replay_cache_path = Path("./.airgap/replay_nonces.json")
        config.security.python_sandbox.mode = "process"
    return config


@app.command()
def run(
    task: str = typer.Argument(..., help="Task for the agent to complete offline."),
    config: Optional[Path] = typer.Option(None, "--config", "-c", help="YAML config path."),
    dev: bool = typer.Option(False, "--dev", help="Relaxed paths for local development."),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable JSON result."),
) -> None:
    """Run the agent harness against a local open-source model."""
    _setup_logging()
    cfg = _load(config, dev)
    try:
        policy = ensure_runtime_ready(cfg, dev=dev)
    except BootstrapError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1) from exc

    backend = create_backend(cfg)
    audit = AuditLogger(cfg.audit)
    harness = AgentHarness(cfg, backend, policy, audit)
    result = harness.run(task)
    if json_output:
        console.print(
            json.dumps(
                {
                    "answer": result.answer,
                    "run_id": result.run_id,
                    "iterations": result.iterations,
                    "tool_calls": result.tool_calls,
                    "budget_denials": result.budget_denials,
                    "structured": result.structured,
                },
                indent=2,
            )
        )
    else:
        console.print(Panel(result.answer, title="Agent result", border_style="green"))
        console.print(
            f"run_id={result.run_id} iterations={result.iterations} "
            f"tool_calls={result.tool_calls} budget_denials={result.budget_denials}"
        )


@app.command()
def health(
    config: Optional[Path] = typer.Option(None, "--config", "-c"),
    dev: bool = typer.Option(False, "--dev"),
) -> None:
    """Report inference and bundle health (loopback only)."""
    _setup_logging()
    cfg = _load(config, dev)
    if dev:
        cfg.airgap.require_bundle_manifest = False
    backend = create_backend(cfg)
    report = health_report(cfg, backend)
    console.print(JSON(json.dumps(report, indent=2)))


@app.command()
def init(
    workspace: Path = typer.Option(Path("./workspace"), "--workspace", "-w"),
    models: Path = typer.Option(Path("./models"), "--models", "-m"),
    trust: Path = typer.Option(Path("./trust"), "--trust", "-t"),
    audit_dir: Path = typer.Option(Path("./.airgap"), "--audit-dir"),
) -> None:
    """Initialize local directories for offline development or staging."""
    for path in (workspace, models, trust, audit_dir):
        path.mkdir(parents=True, exist_ok=True)
    readme = workspace / "README.txt"
    if not readme.exists():
        readme.write_text(
            "Airgap agent workspace — place files here for tool access.\n",
            encoding="utf-8",
        )
    console.print(f"[green]Ready[/green] workspace={workspace} models={models} trust={trust}")


@app.command()
def chat(
    config: Optional[Path] = typer.Option(None, "--config", "-c"),
    dev: bool = typer.Option(False, "--dev"),
    session_id: Optional[str] = typer.Option(None, "--session", help="Resume session id."),
) -> None:
    """Interactive multi-turn agent loop (loopback CLI, no network)."""
    _setup_logging()
    cfg = _load(config, dev)
    try:
        policy = ensure_runtime_ready(cfg, dev=dev)
    except BootstrapError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1) from exc

    backend = create_backend(cfg)
    audit = AuditLogger(cfg.audit)
    harness = AgentHarness(cfg, backend, policy, audit)
    store = SessionStore(
        max_sessions=cfg.api.sessions.max_sessions,
        max_messages=cfg.api.sessions.max_messages_per_session,
        ttl_seconds=cfg.api.sessions.ttl_seconds,
    )
    sid = session_id or store.create()
    console.print(f"Session {sid} — type 'exit' to quit, 'reset' for new session.")

    while True:
        try:
            line = input("you> ").strip()
        except (EOFError, KeyboardInterrupt):
            console.print()
            break
        if not line:
            continue
        if line.lower() in ("exit", "quit"):
            break
        if line.lower() == "reset":
            sid = store.create()
            console.print(f"New session {sid}")
            continue

        history = store.get_history(sid) or []
        result = harness.run(line, history=history)
        store.append(
            sid,
            [
                ChatMessage(role="user", content=line),
                ChatMessage(role="assistant", content=result.answer),
            ],
        )
        console.print(Panel(result.answer, title="assistant", border_style="cyan"))


@app.command()
def eval_cmd(
    cases_path: Path = typer.Argument(
        Path("eval/fixtures"),
        help="YAML file or directory of eval cases.",
    ),
    config: Optional[Path] = typer.Option(None, "--config", "-c"),
    dev: bool = typer.Option(False, "--dev"),
    with_backend: bool = typer.Option(False, "--with-backend", help="Run backend_completion cases."),
) -> None:
    """Run declarative security/behavior eval cases (offline)."""
    _setup_logging()
    cfg = _load(config, dev)
    backend = create_backend(cfg) if with_backend else None
    cases = load_eval_cases(cases_path)
    results = run_eval_cases(cases, config=cfg, backend=backend)
    failed = [r for r in results if not r.ok]
    payload = {
        "ok": len(failed) == 0,
        "passed": sum(1 for r in results if r.ok),
        "failed": len(failed),
        "results": [r.__dict__ for r in results],
    }
    console.print(JSON(json.dumps(payload, indent=2)))
    if failed:
        raise typer.Exit(1)


@app.command("canary")
def canary_cmd(
    config: Optional[Path] = typer.Option(None, "--config", "-c"),
    dev: bool = typer.Option(False, "--dev"),
) -> None:
    """Run lightweight security regression canaries against the configured backend."""
    _setup_logging()
    cfg = _load(config, dev)
    backend = create_backend(cfg)
    results = run_canaries(cfg, backend)
    failed = [r for r in results if not r.ok]
    payload = {"ok": len(failed) == 0, "results": [r.__dict__ for r in results]}
    console.print(JSON(json.dumps(payload, indent=2)))
    if failed:
        raise typer.Exit(1)


@app.command("verify-bundle")
def verify_bundle_cmd(
    models_dir: Optional[Path] = typer.Option(None, "--models-dir"),
    manifest: str = typer.Option("MANIFEST.sha256", "--manifest"),
    trust_dir: Optional[Path] = typer.Option(None, "--trust-dir"),
    require_signature: bool = typer.Option(True, "--require-signature/--no-require-signature"),
) -> None:
    """Verify offline model bundle checksums and Ed25519 signature."""
    settings = BundleSettings()
    trust = TrustSettings()
    if models_dir:
        settings.models_dir = models_dir
    settings.manifest_name = manifest
    if trust_dir:
        trust.public_keys_dir = trust_dir
    trust.require_signed_manifest = require_signature
    result = verify_bundle(settings, trust)
    if result.ok:
        sig = (
            "signed"
            if result.signature_ok
            else ("unsigned" if result.signature_ok is None else "signature ok")
        )
        console.print(f"[green]OK[/green] verified {result.checked} files ({sig})")
        raise typer.Exit(0)
    for err in result.errors:
        console.print(f"[red]{err}[/red]")
    raise typer.Exit(1)


@app.command("write-manifest")
def write_manifest_cmd(
    models_dir: Path = typer.Argument(..., help="Directory containing GGUF/model files."),
    manifest: str = typer.Option("MANIFEST.sha256", "--manifest"),
) -> None:
    """Generate SHA-256 manifest for airgapped model transfer."""
    path = write_manifest(models_dir, manifest)
    console.print(f"Wrote {path}")


@app.command("sign-bundle")
def sign_bundle_cmd(
    models_dir: Path = typer.Argument(..., help="Directory containing model files."),
    private_key: Path = typer.Option(..., "--private-key", "-k", help="Ed25519 PEM (staging only)."),
    key_id: str = typer.Option("release", "--key-id", help="Signer key identifier."),
    manifest: str = typer.Option("MANIFEST.sha256", "--manifest"),
) -> None:
    """Sign model manifest on a connected staging machine (private key never enters airgap)."""
    sig = sign_manifest(models_dir, private_key, key_id, manifest_name=manifest)
    console.print(f"[green]Signed[/green] {sig}")


@app.command("sign-file")
def sign_file_cmd(
    target: Path = typer.Argument(..., help="File to sign (e.g. policies/default.yaml)."),
    private_key: Path = typer.Option(..., "--private-key", "-k"),
    key_id: str = typer.Option("release", "--key-id"),
) -> None:
    """Sign an arbitrary deploy artifact (policy, config) for trustless verification."""
    from airgap_agent.crypto.sign import sign_file, write_envelope

    envelope = sign_file(target, private_key, key_id)
    out = target.parent / f"{target.name}.sig.json"
    write_envelope(envelope, out)
    console.print(f"[green]Wrote[/green] {out}")


@app.command("hf-download")
def hf_download_cmd(
    repo_id: str = typer.Argument(
        ...,
        help="Hugging Face repo, e.g. 'TheBloke/Mistral-7B-Instruct-v0.2-GGUF'.",
    ),
    models_dir: Path = typer.Option(Path("./models"), "--models-dir", help="Destination models directory."),
    revision: Optional[str] = typer.Option(None, "--revision", help="Branch/tag/commit (optional)."),
    pattern: list[str] = typer.Option(
        [],
        "--pattern",
        help="Glob pattern(s) to download (repeatable). Example: '*.gguf' or '*Q4_K_M.gguf'",
    ),
) -> None:
    """
    Connected-host only: download model artifacts from Hugging Face Hub.

    After download: generate+sign the bundle and transfer to the airgapped host.
    """
    from airgap_agent.deployment.hf import HuggingFaceHubUnavailable, hf_snapshot_download

    try:
        result = hf_snapshot_download(
            repo_id=repo_id,
            local_dir=models_dir,
            revision=revision,
            allow_patterns=pattern,
        )
    except HuggingFaceHubUnavailable as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1) from exc

    console.print(
        f"[green]Downloaded[/green] {len(result.downloaded_paths)} files into {result.local_dir}"
        + (f" (commit {result.resolved_commit})" if result.resolved_commit else "")
    )
    console.print("Next: airgap-agent sign-bundle ./models --private-key <signing.pem> --key-id <id>")


@app.command("keys")
def keys_cmd(
    out_dir: Path = typer.Option(Path("."), "--out", "-o"),
    key_id: str = typer.Option("release", "--key-id"),
) -> None:
    """Generate Ed25519 keypair: public key for deploy trust/, private for staging signing/."""
    private_path, public_path = generate_keypair(out_dir, key_id)
    console.print(f"Private (staging only): {private_path}")
    console.print(f"Public  (deploy trust/): {public_path}")


@app.command("mint-token")
def mint_token_cmd(
    caps: list[str] = typer.Option(
        ["fs.read", "fs.list", "fs.search", "py.exec"],
        "--cap",
        help="Capability to grant (repeatable).",
    ),
    ttl: int = typer.Option(300, "--ttl", help="Token TTL seconds."),
    max_tool_calls: int = typer.Option(25, "--max-tool-calls"),
    max_read_bytes: int = typer.Option(1_048_576, "--max-read-bytes"),
    max_python_execs: int = typer.Option(5, "--max-python-execs"),
    api_path: str = typer.Option(
        "/v1/agent/run",
        "--path",
        help="HTTP path this token is valid for (/v1/agent/run or /v1/sessions).",
    ),
) -> None:
    """
    Mint an HMAC-signed capability token for the loopback HTTP API.

    Requires `AIRGAP_API_HMAC_KEY` (32+ random bytes recommended).
    """
    import os
    import uuid
    from airgap_agent.security.capability_tokens import mint_capability_token, parse_hmac_key

    key = os.environ.get("AIRGAP_API_HMAC_KEY", "")
    if not key:
        console.print("[red]set AIRGAP_API_HMAC_KEY to mint tokens[/red]")
        raise typer.Exit(1)

    parsed = parse_hmac_key(key)
    token = mint_capability_token(
        parsed,
        caps=caps,
        ttl_seconds=ttl,
        budgets={
            "max_total_tool_calls_per_run": max_tool_calls,
            "max_total_read_bytes_per_run": max_read_bytes,
            "max_total_python_execs_per_run": max_python_execs,
        },
        nonce=uuid.uuid4().hex,
        method="POST",
        path=api_path,
    )
    console.print(token)


@app.command("verify-audit")
def verify_audit_cmd(
    log_path: Path = typer.Argument(..., help="Audit JSONL log file."),
    decrypt: bool = typer.Option(False, "--decrypt", help="Decrypt ENC1 lines before chain verify."),
) -> None:
    """Verify tamper-evident hash chain in an audit log (no trust required)."""
    import os

    lines = log_path.read_text(encoding="utf-8").splitlines()
    if decrypt:
        raw_key = os.environ.get("AIRGAP_AUDIT_ENCRYPTION_KEY", "")
        if not raw_key:
            console.print("[red]set AIRGAP_AUDIT_ENCRYPTION_KEY to decrypt[/red]")
            raise typer.Exit(1)
        key = parse_key_material(raw_key)
        decrypted: list[str] = []
        for line in lines:
            line = line.strip()
            if not line:
                continue
            if line.startswith("ENC1:"):
                decrypted.append(open_line(key, line))
            else:
                decrypted.append(line)
        lines = decrypted

    ok, count, errors = verify_audit_chain(lines)
    if ok:
        console.print(f"[green]OK[/green] verified {count} chained audit entries")
        raise typer.Exit(0)
    for err in errors:
        console.print(f"[red]{err}[/red]")
    raise typer.Exit(1)


@app.command("verify-policy")
def verify_policy_cmd(
    policy: Path = typer.Argument(...),
    trust_dir: Path = typer.Option(Path("/etc/airgap-agent/trust"), "--trust-dir"),
) -> None:
    """Verify Ed25519 signature on a policy file."""
    ok, errors = verify_signed_artifact(policy, TrustSettings(public_keys_dir=trust_dir))
    if ok:
        console.print("[green]Policy signature valid[/green]")
        raise typer.Exit(0)
    for err in errors:
        console.print(f"[red]{err}[/red]")
    raise typer.Exit(1)


@app.command()
def serve(
    host: str = typer.Option("127.0.0.1", "--host"),
    port: int = typer.Option(8741, "--port"),
    config: Optional[Path] = typer.Option(None, "--config", "-c"),
    dev: bool = typer.Option(False, "--dev"),
) -> None:
    """Minimal loopback HTTP API for health and agent runs (no external deps)."""
    import http.server
    import json as jsonlib

    if host not in ("127.0.0.1", "localhost", "::1"):
        console.print("[red]refusing to bind outside loopback[/red]")
        raise typer.Exit(1)

    cfg = _load(config, dev)
    try:
        policy = ensure_runtime_ready(cfg, dev=dev)
        validate_api_config(cfg)
    except BootstrapError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1) from exc

    backend = create_backend(cfg)
    audit = AuditLogger(cfg.audit)
    from airgap_agent.security.replay_cache import ReplayNonceCache

    replay_cache = ReplayNonceCache(
        cfg.api.replay_cache_path if cfg.api.replay_protection else None,
        max_entries=cfg.api.replay_cache_max_entries,
    )
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

        def _unauthorized(self) -> None:
            self._json(401, {"error": "unauthorized"})

        def _forbidden(self, reason: str = "forbidden") -> None:
            self._json(403, {"error": reason})

        def _bad_request(self, reason: str) -> None:
            self._json(400, {"error": reason})

        def do_GET(self) -> None:
            metrics.inc_api_request()
            if not verify_api_token(cfg, self._headers_map()):
                self._unauthorized()
                return
            if self.path == "/health":
                self._json(200, health_report(cfg, backend))
            elif self.path == "/metrics" and cfg.api.metrics.enabled:
                snap = metrics.snapshot()
                snap.sessions_active = sessions.stats()["active_sessions"]
                body = snap.to_prometheus().encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; version=0.0.4")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            elif self.path.startswith("/v1/sessions/") and cfg.api.sessions.enabled:
                session_id = self.path.removeprefix("/v1/sessions/").strip("/")
                if not session_id:
                    self._json(404, {"error": "not found"})
                    return
                history = sessions.get_history(session_id)
                if history is None:
                    self._json(404, {"error": "unknown session_id"})
                    return
                self._json(
                    200,
                    {
                        "session_id": session_id,
                        "message_count": len(history),
                        "ttl_seconds": cfg.api.sessions.ttl_seconds,
                    },
                )
            else:
                self._json(404, {"error": "not found"})

        def do_DELETE(self) -> None:
            metrics.inc_api_request()
            if not verify_api_token(cfg, self._headers_map()):
                self._unauthorized()
                return
            if not self.path.startswith("/v1/sessions/") or not cfg.api.sessions.enabled:
                self._json(404, {"error": "not found"})
                return
            session_id = self.path.removeprefix("/v1/sessions/").strip("/")
            if not session_id or not sessions.delete(session_id):
                self._json(404, {"error": "unknown session_id"})
                return
            self._json(200, {"deleted": session_id})

        def _verify_capability_for_path(self, expected_path: str) -> dict | None:
            try:
                claims = verify_capability_token_from_headers(cfg, self._headers_map())
            except BootstrapError:
                return None
            if cfg.api.enforce_capability_token_scope:
                if claims.get("method") and str(claims["method"]).upper() != "POST":
                    return None
                if claims.get("path") and str(claims["path"]) != expected_path:
                    return None
            return claims

        def do_POST(self) -> None:
            metrics.inc_api_request()
            if not verify_api_token(cfg, self._headers_map()):
                self._unauthorized()
                return

            if self.path == "/v1/sessions" and cfg.api.sessions.enabled:
                if cfg.api.require_capability_token:
                    if self._verify_capability_for_path("/v1/sessions") is None:
                        self._forbidden("capability token required or invalid for /v1/sessions")
                        return
                sid = sessions.create()
                self._json(
                    201,
                    {
                        "session_id": sid,
                        "ttl_seconds": cfg.api.sessions.ttl_seconds,
                    },
                )
                return

            if self.path != "/v1/agent/run":
                self._json(404, {"error": "not found"})
                return

            if cfg.api.require_capability_token:
                claims = self._verify_capability_for_path("/v1/agent/run")
                if claims is None:
                    self._forbidden("capability token required or invalid for /v1/agent/run")
                    return
            else:
                claims = verify_capability_token_from_headers(cfg, self._headers_map())

            if cfg.api.replay_protection and cfg.api.require_capability_token:
                nonce = claims.get("nonce")
                exp = int(claims.get("exp", 0))
                if not nonce or not replay_cache.accept(str(nonce), exp):
                    self._forbidden("replay detected or missing nonce")
                    return

            try:
                length = int(self.headers.get("Content-Length", 0))
            except ValueError:
                self._bad_request("invalid Content-Length")
                return
            if length > cfg.agent.max_task_chars + 4096:
                self._json(413, {"error": "payload too large"})
                return
            try:
                raw = self.rfile.read(length).decode()
                data = jsonlib.loads(raw) if raw else {}
            except (UnicodeDecodeError, jsonlib.JSONDecodeError):
                self._bad_request("invalid JSON body")
                return
            if not isinstance(data, dict):
                self._bad_request("JSON body must be an object")
                return
            task = data.get("task", "")
            if not task:
                self._json(400, {"error": "task required"})
                return

            history: list[ChatMessage] | None = None
            session_id = data.get("session_id")
            if session_id and cfg.api.sessions.enabled:
                history = sessions.get_history(str(session_id))
                if history is None:
                    self._json(404, {"error": "unknown session_id"})
                    return

            # Apply request scope by intersecting global config with signed claims.
            scoped = cfg.model_copy(deep=True)
            token_caps = set(claims.get("caps", []))
            scoped.security.allowed_capabilities = sorted(
                set(cfg.security.allowed_capabilities).intersection(token_caps)
            )
            budgets = claims.get("budgets", {}) or {}
            scoped.security.max_total_tool_calls_per_run = min(
                scoped.security.max_total_tool_calls_per_run,
                int(budgets.get("max_total_tool_calls_per_run", scoped.security.max_total_tool_calls_per_run)),
            )
            scoped.security.max_total_read_bytes_per_run = min(
                scoped.security.max_total_read_bytes_per_run,
                int(budgets.get("max_total_read_bytes_per_run", scoped.security.max_total_read_bytes_per_run)),
            )
            scoped.security.max_total_python_execs_per_run = min(
                scoped.security.max_total_python_execs_per_run,
                int(budgets.get("max_total_python_execs_per_run", scoped.security.max_total_python_execs_per_run)),
            )

            metrics.inc_run()
            harness = AgentHarness(scoped, backend, policy, audit, metrics=metrics)
            try:
                result = harness.run(task, history=history)
            except ValueError as exc:
                metrics.inc_run_failed()
                self._bad_request(str(exc))
                return
            metrics.inc_tool_calls(result.tool_calls)
            if session_id and cfg.api.sessions.enabled:
                sessions.append(
                    str(session_id),
                    [
                        ChatMessage(role="user", content=str(task)),
                        ChatMessage(role="assistant", content=result.answer),
                    ],
                )
            self._json(
                200,
                {
                    "answer": result.answer,
                    "structured": result.structured,
                    "run_id": result.run_id,
                    "session_id": session_id,
                    "iterations": result.iterations,
                    "tool_calls": result.tool_calls,
                    "budget_denials": result.budget_denials,
                    "caps": scoped.security.allowed_capabilities,
                },
            )

    server = http.server.ThreadingHTTPServer((host, port), Handler)
    token_note = " (Bearer token required)" if cfg.api.require_token else ""
    console.print(f"Serving on http://{host}:{port}{token_note}")
    server.serve_forever()


if __name__ == "__main__":
    app()
