# Layer 5 hardening: non-root inference container.
# DEPLOY-04: base image PINNED (digest-pinning is the next step once a
# mirror/registry is chosen - see docs/ROADMAP.md supply-chain row).
FROM python:3.12.14-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Run as unprivileged user (never root) - container-escape blast radius ~= 0
RUN useradd --create-home appuser && chown -R appuser:appuser /app
USER appuser

# Defaults; docker-compose.yml overrides via environment
ENV HOST=0.0.0.0 \
    PORT=8000 \
    MODEL_PROVIDER=auto \
    OLLAMA_URL=http://ollama:11434 \
    OLLAMA_MODEL=qwen2.5:0.5b \
    SECRETS_DIR=/tmp/secrets

EXPOSE 8000

# Container orchestrator (and humans) can see app liveness without auth
HEALTHCHECK --interval=10s --timeout=5s --retries=6 \
  CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8000/health')"

CMD ["python", "run.py"]
