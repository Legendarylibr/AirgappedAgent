# Threat Model (summary)

## Goals

- **Airgapped by default**: no outbound network requirements at runtime.
- **Trustless verification**: model bundles and policies can be verified using **offline public keys**.
- **Least privilege tools**: a small allowlist with bounded IO.
- **Prompt injection resilience**: treat workspace and tool outputs as untrusted.

## Adversaries

- **Malicious user input**: attempts to trigger unauthorized tool calls or bypass policies.
- **Poisoned workspace content**: files containing instruction-bearing content.
- **Compromised staging artifacts**: tampered bundles, policies, configs in transit (USB/sneakernet).
- **Compromised local model**: outputs adversarial structured text designed to trigger actions.

## Trust boundaries

1. **User task → Model**: user text is untrusted.
2. **Model output → Tool router**: tool calls must be validated (schema + allowlist).
3. **Tools → Filesystem**: workspace jail, no symlinks, bounded reads/list/search.
4. **Runtime → Artifacts**: bundles/policies are verified via signatures.
5. **Runtime → Logs**: audit is tamper-evident; encryption optional.

## Non-goals / out of scope

- Malicious kernel/hypervisor (use OS hardening, VMs, hardware attestation if needed).
- Side-channel resistance (timing/power/cache).
- Browser automation / arbitrary network tools (not implemented).

## Key mitigations in this repo

- Tool gate: `src/airgap_agent/agent/tool_gate.py`
- Tool allowlist + bounded IO: `src/airgap_agent/agent/tools.py`
- Signed policy verification: `src/airgap_agent/security/policy.py`
- Signed bundles: `src/airgap_agent/deployment/bundle.py`
- Audit hash chain (+ optional encryption): `src/airgap_agent/security/audit.py`

