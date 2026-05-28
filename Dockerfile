FROM python:3.12-slim-bookworm AS builder

WORKDIR /build
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential cmake git \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir .

FROM python:3.12-slim-bookworm

RUN groupadd -r airgap && useradd -r -g airgap -d /var/lib/airgap-agent airgap \
    && mkdir -p /var/lib/airgap-agent/models /var/lib/airgap-agent/workspace /var/log/airgap-agent \
    && chown -R airgap:airgap /var/lib/airgap-agent /var/log/airgap-agent

WORKDIR /app
COPY --from=builder /usr/local /usr/local
COPY config ./config
COPY policies ./policies

ENV AIRGAP_AIRGAP__MODE=strict \
    AIRGAP_AIRGAP__DENY_EGRESS=true \
    AIRGAP_INFERENCE__BACKEND=mock \
    AIRGAP_SECURITY__WORKSPACE_ROOT=/var/lib/airgap-agent/workspace \
    AIRGAP_BUNDLE__MODELS_DIR=/var/lib/airgap-agent/models \
    AIRGAP_AUDIT__LOG_PATH=/var/log/airgap-agent/audit.jsonl

USER airgap
EXPOSE 8741
ENTRYPOINT ["airgap-agent"]
CMD ["serve", "--host", "127.0.0.1", "--port", "8741"]
