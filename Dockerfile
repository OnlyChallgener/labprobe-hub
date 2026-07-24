FROM python:3.12-slim-bookworm

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
RUN pip install --no-cache-dir -r /app/requirements.txt \
    && rm -rf /root/.cache/pip

COPY hub.py /app/hub.py
COPY hub_entry.py /app/hub_entry.py
COPY hub_realtime_ws.py /app/hub_realtime_ws.py
COPY router_rpc.py /app/router_rpc.py
COPY router_rpc_v099.py /app/router_rpc_v099.py
COPY router_rpc_v010.py /app/router_rpc_v010.py
COPY router_developer_flow_patch.py /app/router_developer_flow_patch.py
COPY router_http_developer_transport_patch.py /app/router_http_developer_transport_patch.py
COPY router_be72_auth_patch.py /app/router_be72_auth_patch.py
COPY router_be72_sid_wire_patch.py /app/router_be72_sid_wire_patch.py
COPY router_native_features_patch.py /app/router_native_features_patch.py
COPY router_ws_patch.py /app/router_ws_patch.py
COPY router_fast_watchdog_patch.py /app/router_fast_watchdog_patch.py
COPY router_build024_fix.py /app/router_build024_fix.py
COPY router_compat.py /app/router_compat.py
COPY router_realtime_stability_patch.py /app/router_realtime_stability_patch.py
COPY router_relay_credentials_patch.py /app/router_relay_credentials_patch.py
COPY router_lite_realtime_patch.py /app/router_lite_realtime_patch.py
COPY labprobe_storage.py /app/labprobe_storage.py
COPY scripts/repair_storage.py /app/scripts/repair_storage.py

RUN python -m py_compile \
        /app/hub.py \
        /app/hub_entry.py \
        /app/hub_realtime_ws.py \
        /app/router_rpc.py \
        /app/router_rpc_v099.py \
        /app/router_rpc_v010.py \
        /app/router_developer_flow_patch.py \
        /app/router_http_developer_transport_patch.py \
        /app/router_be72_auth_patch.py \
        /app/router_be72_sid_wire_patch.py \
        /app/router_native_features_patch.py \
        /app/router_ws_patch.py \
        /app/router_fast_watchdog_patch.py \
        /app/router_build024_fix.py \
        /app/router_compat.py \
        /app/router_realtime_stability_patch.py \
        /app/router_relay_credentials_patch.py \
        /app/router_lite_realtime_patch.py \
        /app/labprobe_storage.py \
    && python -c "import router_lite_realtime_patch, router_fast_watchdog_patch, router_build024_fix, hub_realtime_ws" \
    && mkdir -p /app/data /app/config /app/backups /app/logs /app/scripts \
    && chmod 755 /app/scripts/repair_storage.py

EXPOSE 58443

HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 \
    CMD curl -fsS "http://127.0.0.1:${PORT}/health" >/dev/null || exit 1

CMD ["python", "/app/hub_entry.py"]
