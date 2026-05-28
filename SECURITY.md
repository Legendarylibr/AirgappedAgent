# Security Policy

## Supported versions

This project is currently **pre-1.0**. We aim to fix security issues quickly on the `main` branch.

## Reporting a vulnerability

Please **do not** open a public issue with sensitive details.

- **Preferred**: Open a private security advisory on the hosting platform (if available).
- **Otherwise**: Email the maintainer(s) with:
  - affected version / commit
  - impact and threat model
  - minimal reproduction details (no exploit payloads)

We will respond with a triage timeline and a coordinated disclosure plan.

## Threat model (high level)

Airgap Agent is designed for **offline / airgapped** inference and agent tool execution.

Assumptions:
- The **LLM output is untrusted**.
- Workspace content and tool output may be **prompt-injection** carriers.
- The runtime host may be **semi-trusted**; artifacts should be verifiable with offline public keys.

Out of scope:
- A fully malicious host OS/hypervisor (use hardware + OS hardening).
- Side-channel resistance against local attackers.

See `docs/THREAT_MODEL.md` for details.

