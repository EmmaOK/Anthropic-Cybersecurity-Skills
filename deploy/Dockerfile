# Phantom app image — one image, two runtime roles (API and worker) selected by
# the container command. Build context is the REPO ROOT (see docker-compose.yml).
#
#   API    : uvicorn phantom.server:app --host 0.0.0.0 --port 8080
#   Worker : python phantom/worker.py       (needs REDIS_URL so it runs the loop)
#
# A clean 3.12 base also sidesteps the broken-Homebrew-Python/venv issue that
# only affects dev laptops.
FROM python:3.12-slim

WORKDIR /app
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1

# Install deps first for layer caching. Server extras + optional redis on top of
# phantom/requirements.txt (anthropic, httpx, google-* ...).
COPY phantom/requirements.txt /app/phantom/requirements.txt
RUN pip install --no-cache-dir -r /app/phantom/requirements.txt \
    fastapi "uvicorn[standard]" jinja2 python-multipart aiofiles redis \
    "psycopg[binary]" boto3   # DB (Postgres) + blob (S3) drivers for prod backends

# App code + skill library + generated index.json (skill_loader reads it).
COPY . /app

EXPOSE 8080
# Default role is the API; the worker service overrides `command`.
CMD ["uvicorn", "phantom.server:app", "--host", "0.0.0.0", "--port", "8080"]
