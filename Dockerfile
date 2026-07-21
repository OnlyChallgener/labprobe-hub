FROM python:3.12-slim

ARG TARGETARCH
ARG TARGETOS

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=58443 \
    CONFIG_DIR=./config \
    DATA_DIR=./data \
    BACKUPS_DIR=./backups \
    LOGS_DIR=./logs \
    CONFIG_PATH=./config/config.yaml

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates iproute2 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY hub.py /app/hub.py
COPY hub_entry.py /app/hub_entry.py
COPY router_rpc.py /app/router_rpc.py
COPY router_compat.py /app/router_compat.py
COPY labprobe_storage.py /app/labprobe_storage.py
COPY scripts/repair_storage.py /app/scripts/repair_storage.py

RUN mkdir -p /app/data /app/config /app/backups /app/logs /app/scripts \
    && chmod 755 /app/scripts/repair_storage.py

EXPOSE 58443

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS "http://127.0.0.1:${PORT}/health" >/dev/null || exit 1

CMD ["python", "/app/hub_entry.py"]
