FROM python:3.12-slim

ENV POETRY_VERSION=1.8.3 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends build-essential && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py /app/main.py

EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "${UVICORN_HOST:-0.0.0.0}", "--port", "${UVICORN_PORT:-8000}"]
