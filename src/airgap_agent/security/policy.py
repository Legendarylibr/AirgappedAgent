from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

import yaml

from airgap_agent.config import TrustSettings

Effect = Literal["allow", "deny"]


@dataclass(frozen=True)
class PolicyDecision:
    effect: Effect
    rule_id: str | None
    reason: str


class PolicyEngine:
    """YAML policy evaluator; optionally verifies Ed25519 signature before load."""

    def __init__(self, policy_path: Path, trust: TrustSettings | None = None) -> None:
        self._policy_path = policy_path.resolve()
        if trust and trust.require_signed_policy:
            from airgap_agent.deployment.bundle import verify_signed_artifact

            ok, errors = verify_signed_artifact(self._policy_path, trust)
            if not ok:
                raise PermissionError("policy signature verification failed: " + "; ".join(errors))
        self._doc = self._load(self._policy_path)

    @staticmethod
    def _load(path: Path) -> dict[str, Any]:
        with path.open() as f:
            return yaml.safe_load(f) or {}

    def evaluate(
        self,
        action: str,
        context: dict[str, Any] | None = None,
    ) -> PolicyDecision:
        ctx = context or {}
        rules = self._doc.get("rules", [])
        default_effect: Effect = self._doc.get("defaults", {}).get("effect", "deny")

        matched: list[tuple[Effect, str]] = []
        for rule in rules:
            if not self._rule_matches(rule, action, ctx):
                continue
            effect: Effect = rule.get("effect", "deny")
            matched.append((effect, rule.get("id", "unknown")))

        if not matched:
            return PolicyDecision(
                effect=default_effect,
                rule_id=None,
                reason=f"no rule matched; default={default_effect}",
            )

        for effect, rule_id in matched:
            if effect == "deny":
                return PolicyDecision(effect="deny", rule_id=rule_id, reason="deny rule matched")

        effect, rule_id = matched[-1]
        return PolicyDecision(effect=effect, rule_id=rule_id, reason="allow rule matched")

    def _rule_matches(self, rule: dict[str, Any], action: str, ctx: dict[str, Any]) -> bool:
        actions = rule.get("actions", [])
        if action not in actions:
            return False
        when = rule.get("when", {})
        if when.get("always"):
            return True
        tool_names = when.get("tool.name_in")
        if tool_names is not None:
            return ctx.get("tool_name") in tool_names
        caps = when.get("capability.in")
        if caps is not None:
            return ctx.get("capability") in caps
        if when.get("path.under_workspace"):
            workspace = Path(ctx.get("workspace_root", "."))
            target = Path(ctx.get("path", "."))
            try:
                target.resolve().relative_to(workspace.resolve())
                return True
            except ValueError:
                return False
        return False
