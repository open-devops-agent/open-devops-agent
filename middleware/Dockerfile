# Base image pinned by digest; Dependabot (docker ecosystem) proposes updates.
FROM python:3.13-slim@sha256:7249d5587b78209a006dc4a3b5340678f84ea729239193aa559962cd8c1fce50

WORKDIR /app
# Apply Debian security updates released after the base image was built.
RUN apt-get update && apt-get upgrade -y --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*
RUN useradd -m -u 1000 appuser

# Locked, hash-verified install (#121); regenerate with scripts/lock.sh.
COPY requirements.lock .
RUN pip install --no-cache-dir --require-hashes --no-deps -r requirements.lock

COPY app.py .

USER appuser
ENV HOST=0.0.0.0 PORT=8080
EXPOSE 8080

CMD ["sh", "-c", "uvicorn app:app --host ${HOST:-0.0.0.0} --port ${PORT:-8080}"]
