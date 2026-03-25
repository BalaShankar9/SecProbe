FROM python:3.12-slim AS base

# Prevent Python from writing .pyc files and enable unbuffered output
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc && \
    rm -rf /var/lib/apt/lists/*

# Copy dependency files first for Docker layer caching
COPY api/requirements.txt /app/api/requirements.txt
COPY requirements.txt /app/requirements.txt

# Install Python dependencies
RUN pip install --no-cache-dir -r /app/requirements.txt && \
    pip install --no-cache-dir -r /app/api/requirements.txt

# Copy application code
COPY secprobe/ /app/secprobe/
COPY api/ /app/api/

# Ensure secprobe is importable
ENV PYTHONPATH=/app

EXPOSE 8000

# Railway injects PORT env var; default to 8000
ENV PORT=8000

CMD uvicorn api.main:app --host 0.0.0.0 --port ${PORT} --workers 2 --loop uvloop --http httptools
