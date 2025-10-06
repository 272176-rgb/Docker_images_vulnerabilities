FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# narzędzia do budowania (zwykle niepotrzebne, ale bezpiecznie mieć)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential curl && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN python -m pip install --upgrade pip setuptools wheel && \
    pip install --no-cache-dir -r requirements.txt

# skopiuj kod aplikacji
COPY app /app/app

EXPOSE 8000
# komenda startowa jest w docker-compose.yml (waitress-serve)
