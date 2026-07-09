FROM python:3.12-slim

WORKDIR /app

# System dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install
COPY phantom/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY phantom/ ./
COPY skills/ ../skills/
# skill_loader.py reads ROOT/index.json (repo root) at import time
COPY index.json ../index.json

# Create non-root user
RUN useradd -u 1001 -m -s /sbin/nologin phantom && chown -R phantom:phantom /app
USER phantom

# Health check
HEALTHCHECK --interval=30s --timeout=5s --retries=3 --start-period=15s \
    CMD python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/health')" || exit 1

EXPOSE 8080

CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8080"]
