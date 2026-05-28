# Secure Startup Guide

This guide is optimized for **trustless, verifiable deployment**: the airgapped host is treated as semi-trusted, while a connected staging machine prepares signed artifacts.

## Roles

- **Staging (connected)**: downloads models, builds wheelhouse/images, signs artifacts with **private keys**.
- **Airgapped (offline)**: runs inference + agent harness, verifies artifacts using **public keys only**.

## Quick checklist (airgapped)

- [ ] Models directory present and read-only
- [ ] `MANIFEST.sha256` + `MANIFEST.sig.json` present
- [ ] Public keys installed at `/etc/airgap-agent/trust/`
- [ ] Policy file is signed (`policies/default.yaml.sig.json`)
- [ ] `config/default.yaml` reviewed (loopback bind, token auth on)
- [ ] Audit logging path writable (or mounted)
- [ ] No outbound network path (prefer container `network_mode: none`)

## Staging: prepare keys

```bash
airgap-agent keys --out ./release-keys --key-id prod-2025
```

- **Keep** `./release-keys/signing/prod-2025.pem` offline (staging only).
- **Deploy** `./release-keys/trust/prod-2025.pub.pem` to airgapped hosts.

## Staging: acquire models (two options)

### Option A: Bring your own GGUF

Copy weights into `./models/`.

### Option B: Hugging Face Hub (connected only)

```bash
pip install -e ".[hf]"
airgap-agent hf-download "TheBloke/Mistral-7B-Instruct-v0.2-GGUF" \
  --models-dir ./models \
  --pattern "*.gguf" \
  --pattern "*Q4_K_M.gguf"
```

This writes `./models/HF_SOURCE.json` (provenance).

## Staging: sign artifacts

```bash
./scripts/sign-bundle.sh ./models ./release-keys/signing/prod-2025.pem prod-2025
airgap-agent sign-file policies/default.yaml -k ./release-keys/signing/prod-2025.pem --key-id prod-2025
```

Transfer to airgapped host:
- `models/` (including `HF_SOURCE.json` if used)
- `models/MANIFEST.sha256`
- `models/MANIFEST.sig.json`
- `policies/default.yaml` + `policies/default.yaml.sig.json`
- `trust/*.pub.pem`
- optional: offline wheelhouse / docker image tarballs

## Airgapped: verify before run

```bash
sudo mkdir -p /etc/airgap-agent/trust
sudo cp trust/*.pub.pem /etc/airgap-agent/trust/

airgap-agent verify-policy policies/default.yaml --trust-dir /etc/airgap-agent/trust
airgap-agent verify-bundle --models-dir ./models --trust-dir /etc/airgap-agent/trust
```

## Airgapped: run

```bash
export AIRGAP_INFERENCE__BACKEND=llama_cpp
export AIRGAP_INFERENCE__MODEL_PATH=/var/lib/airgap-agent/models/model.gguf

# If using the loopback API:
export AIRGAP_API_TOKEN=$(openssl rand -hex 32)
export AIRGAP_API_HMAC_KEY=$(openssl rand -hex 32)

airgap-agent run "Your offline task"
```

## Optional: strongest isolation for `run_python`

Set:

```yaml
security:
  python_sandbox:
    mode: docker
    docker_image: python:3.12-slim
```

Preload the image on the host before airgapping.

