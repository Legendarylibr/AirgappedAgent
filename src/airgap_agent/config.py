from __future__ import annotations

from pathlib import Path
from typing import Literal

import yaml
from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class AirgapSettings(BaseSettings):
    mode: Literal["strict", "permissive"] = "strict"
    deny_egress: bool = True
    bind_host: str = "127.0.0.1"
    require_bundle_manifest: bool = True


class InferenceSettings(BaseSettings):
    backend: Literal["mock", "llama_cpp", "openai_compat"] = "mock"
    model_path: Path = Path("/var/lib/airgap-agent/models/model.gguf")
    n_ctx: int = 8192
    n_gpu_layers: int = 0
    temperature: float = 0.2
    max_tokens: int = 2048
    chat_template: Literal["generic", "chatml", "llama3", "mistral"] = "generic"
    base_url: str = "http://127.0.0.1:8080/v1"
    api_key_env: str = "AIRGAP_INFERENCE_API_KEY"

    @field_validator("base_url")
    @classmethod
    def base_url_must_be_loopback(cls, v: str) -> str:
        lowered = v.lower()
        if not (
            lowered.startswith("http://127.0.0.1")
            or lowered.startswith("http://localhost")
            or lowered.startswith("https://127.0.0.1")
            or lowered.startswith("https://localhost")
        ):
            raise ValueError("inference.base_url must target loopback only in airgapped mode")
        return v


class PythonSandboxSettings(BaseSettings):
    deny_imports: list[str] = Field(
        default_factory=lambda: [
            "socket",
            "subprocess",
            "urllib",
            "http",
            "ftplib",
            "smtplib",
            "requests",
            "httpx",
        ]
    )

    mode: Literal["process", "docker"] = "process"
    docker_image: str = "python:3.12-slim"


class SecuritySettings(BaseSettings):
    allowed_tools: list[str] = Field(
        default_factory=lambda: ["read_file", "list_directory", "search_text", "run_python"]
    )
    tool_timeout_seconds: int = 30
    workspace_root: Path = Path("/var/lib/airgap-agent/workspace")
    max_write_bytes: int = 262_144
    write_allowed_extensions: list[str] = Field(
        default_factory=lambda: [".txt", ".md", ".json", ".yaml", ".yml", ".py", ".log", ".toml"]
    )
    max_read_bytes: int = 1_048_576
    max_list_entries: int = 500
    max_search_hits: int = 50
    max_search_files: int = 2000
    max_total_tool_calls_per_run: int = 50
    max_total_read_bytes_per_run: int = 4_194_304
    max_total_python_execs_per_run: int = 10
    allowed_capabilities: list[str] = Field(
        default_factory=lambda: ["fs.read", "fs.list", "fs.search", "py.exec"]
    )
    search_allowed_extensions: list[str] = Field(
        default_factory=lambda: [".py", ".md", ".txt", ".json", ".yaml", ".yml", ".log", ".toml"]
    )
    python_sandbox: PythonSandboxSettings = Field(default_factory=PythonSandboxSettings)


class SessionSettings(BaseSettings):
    enabled: bool = True
    max_sessions: int = 100
    max_messages_per_session: int = 50
    ttl_seconds: int = 3600


class MetricsSettings(BaseSettings):
    enabled: bool = True


class ApiSettings(BaseSettings):
    require_token: bool = True
    token_env: str = "AIRGAP_API_TOKEN"
    require_capability_token: bool = True
    capability_token_env: str = "AIRGAP_API_HMAC_KEY"
    capability_token_header: str = "X-Airgap-Capability-Token"
    enforce_capability_token_scope: bool = True
    replay_protection: bool = False
    replay_cache_max_entries: int = 5000
    sessions: SessionSettings = Field(default_factory=SessionSettings)
    metrics: MetricsSettings = Field(default_factory=MetricsSettings)


class TrustSettings(BaseSettings):
    public_keys_dir: Path = Path("/etc/airgap-agent/trust")
    require_signed_manifest: bool = True
    require_signed_policy: bool = True


class AuditSettings(BaseSettings):
    enabled: bool = True
    log_path: Path = Path("/var/log/airgap-agent/audit.jsonl")
    include_prompts: bool = False
    hash_chain: bool = True
    encrypt_at_rest: bool = False
    encryption_key_env: str = "AIRGAP_AUDIT_ENCRYPTION_KEY"


class BundleSettings(BaseSettings):
    models_dir: Path = Path("/var/lib/airgap-agent/models")
    manifest_name: str = "MANIFEST.sha256"
    signature_name: str = "MANIFEST.sig.json"


class AgentSettings(BaseSettings):
    max_iterations: int = 12
    max_tool_output_chars: int = 16000
    max_task_chars: int = 32_000
    max_invalid_tool_calls: int = 3
    system_prompt_path: Path | None = None
    response_format: Literal["text", "json"] = "text"


class AppConfig(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="AIRGAP_",
        env_nested_delimiter="__",
        extra="ignore",
    )

    airgap: AirgapSettings = Field(default_factory=AirgapSettings)
    inference: InferenceSettings = Field(default_factory=InferenceSettings)
    agent: AgentSettings = Field(default_factory=AgentSettings)
    security: SecuritySettings = Field(default_factory=SecuritySettings)
    audit: AuditSettings = Field(default_factory=AuditSettings)
    bundle: BundleSettings = Field(default_factory=BundleSettings)
    trust: TrustSettings = Field(default_factory=TrustSettings)
    api: ApiSettings = Field(default_factory=ApiSettings)
    policy_path: Path = Path("policies/default.yaml")

    @model_validator(mode="after")
    def strict_mode_checks(self) -> AppConfig:
        if self.airgap.mode == "strict" and not self.airgap.deny_egress:
            raise ValueError("deny_egress must be true when airgap.mode is strict")
        if self.airgap.mode == "strict" and not self.api.replay_protection:
            self.api.replay_protection = True
        return self


def load_config(path: Path | None = None) -> AppConfig:
    data: dict = {}
    if path and path.exists():
        with path.open() as f:
            loaded = yaml.safe_load(f) or {}
        data = loaded
    elif Path("config/default.yaml").exists():
        with Path("config/default.yaml").open() as f:
            loaded = yaml.safe_load(f) or {}
        data = loaded
    return AppConfig(**data)
