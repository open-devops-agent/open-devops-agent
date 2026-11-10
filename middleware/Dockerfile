# Base image pinned by digest; Dependabot (docker ecosystem) proposes updates.
FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b

WORKDIR /app
# Apply Debian security updates released after the base image was built.
RUN apt-get update && apt-get upgrade -y --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*
RUN useradd -m -u 1000 appuser

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

USER appuser
ENV HOST=0.0.0.0 PORT=8080
EXPOSE 8080

CMD ["sh", "-c", "uvicorn app:app --host ${HOST:-0.0.0.0} --port ${PORT:-8080}"]
