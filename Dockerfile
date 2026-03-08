FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    NETSENTINEL_APP_ENV=production \
    NETSENTINEL_HOST=0.0.0.0 \
    NETSENTINEL_PORT=8000 \
    NETSENTINEL_DATA_DIR=/app/data \
    NETSENTINEL_RUNTIME_DIR=/app/data/runtime \
    NETSENTINEL_PERSIST_RUNTIME=true

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc libpcap-dev curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN pip install -r requirements.txt

COPY app ./app
COPY data ./data
COPY scripts ./scripts
COPY deploy/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh && mkdir -p /app/data/runtime

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD curl -fsS http://127.0.0.1:8000/api/health || exit 1

ENTRYPOINT ["/entrypoint.sh"]
CMD ["gunicorn", "-k", "uvicorn.workers.UvicornWorker", "-w", "2", "-b", "0.0.0.0:8000", "app.main:app"]
