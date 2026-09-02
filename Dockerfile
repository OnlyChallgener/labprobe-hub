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
    UPDATE_REPOSITORY_DIR=/app/update-repository \
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
COPY ipv6_neighbor_archive_patch.py /app/ipv6_neighbor_archive_patch.py
COPY stun_service.py /app/stun_service.py
COPY stun_port_config_patch.py /app/stun_port_config_patch.py
COPY wireguard_service.py /app/wireguard_service.py
COPY portmap_firewall.py /app/portmap_firewall.py
COPY tcp_session_service.py /app/tcp_session_service.py
COPY hub_realtime_ws.py /app/hub_realtime_ws.py
COPY hub0934_fixes.py /app/hub0934_fixes.py
COPY hub0935_sync_fix.py /app/hub0935_sync_fix.py
COPY followup_stability_patch.py /app/followup_stability_patch.py
COPY final_stability_patch.py /app/final_stability_patch.py
COPY labrelay_sync_patch.py /app/labrelay_sync_patch.py
COPY lab_ddns.py /app/lab_ddns.py
COPY lab_ddns_providers.py /app/lab_ddns_providers.py
COPY scripts/labprobe-install.sh /app/agent/install.sh
COPY agent_presence_patch.py /app/agent_presence_patch.py
COPY device_history_patch.py /app/device_history_patch.py
COPY portmap_persistence_patch.py /app/portmap_persistence_patch.py
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
COPY router_device_live_sync_patch.py /app/router_device_live_sync_patch.py
COPY router_slow_cache_patch.py /app/router_slow_cache_patch.py
COPY router_control_scheduler_patch.py /app/router_control_scheduler_patch.py
COPY router_control_actor_patch.py /app/router_control_actor_patch.py
COPY router_task_manager_patch.py /app/router_task_manager_patch.py
COPY router_config_sync_patch.py /app/router_config_sync_patch.py
COPY router /app/router
COPY assistant /app/assistant
COPY router_core /app/router_core
COPY labprobe_storage.py /app/labprobe_storage.py
COPY scripts/repair_storage.py /app/scripts/repair_storage.py

RUN python -m py_compile \
        /app/hub.py \
        /app/hub_entry.py \
        /app/ipv6_neighbor_archive_patch.py \
        /app/stun_service.py \
        /app/stun_port_config_patch.py \
        /app/wireguard_service.py \
        /app/portmap_firewall.py \
        /app/tcp_session_service.py \
        /app/hub_realtime_ws.py \
        /app/hub0934_fixes.py \
        /app/hub0935_sync_fix.py \
        /app/followup_stability_patch.py \
        /app/final_stability_patch.py \
        /app/labrelay_sync_patch.py \
        /app/lab_ddns.py \
        /app/lab_ddns_providers.py \
        /app/agent_presence_patch.py \
        /app/device_history_patch.py \
        /app/portmap_persistence_patch.py \
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
        /app/router_device_live_sync_patch.py \
        /app/router_slow_cache_patch.py \
        /app/router_control_scheduler_patch.py \
        /app/router_control_actor_patch.py \
        /app/router_task_manager_patch.py \
        /app/router_config_sync_patch.py \
        /app/router/__init__.py \
        /app/router/ipv6/__init__.py \
        /app/router/ipv6/models.py \
        /app/router/ipv6/mapper.py \
        /app/router/ipv6/service.py \
        /app/router/ipv6/api.py \
        /app/assistant/__init__.py \
        /app/assistant/api.py \
        /app/assistant/catalog.py \
        /app/assistant/provider.py \
        /app/assistant/notifications.py \
        /app/assistant/security.py \
        /app/assistant/storage.py \
        /app/assistant/tools.py \
        /app/router_core/__init__.py \
        /app/router_core/errors.py \
        /app/router_core/contracts.py \
        /app/router_core/driver/__init__.py \
        /app/router_core/driver/reyee_session.py \
        /app/router_core/driver/reyee_rpc.py \
        /app/router_core/driver/reyee.py \
        /app/router_core/cache/__init__.py \
        /app/router_core/cache/router_cache.py \
        /app/router_core/realtime/__init__.py \
        /app/router_core/realtime/router_realtime.py \
        /app/router_core/service/__init__.py \
        /app/router_core/service/router_service.py \
        /app/router_core/service/blueprint.py \
        /app/labprobe_storage.py \
    && python -c "import hub0934_fixes, hub0935_sync_fix, followup_stability_patch, final_stability_patch, labrelay_sync_patch, lab_ddns, lab_ddns_providers, agent_presence_patch, device_history_patch, portmap_persistence_patch, portmap_firewall, stun_port_config_patch, tcp_session_service, router_lite_realtime_patch, router_device_live_sync_patch, router_fast_watchdog_patch, router_build024_fix, router_slow_cache_patch, router_control_scheduler_patch, router_control_actor_patch, router_task_manager_patch, router_config_sync_patch, ipv6_neighbor_archive_patch, router.ipv6, hub_realtime_ws, assistant, router_core, router_core.driver.reyee_session, router_core.driver.reyee_rpc, router_core.driver.reyee, router_core.cache.router_cache, router_core.realtime.router_realtime, router_core.service.router_service, router_core.service.blueprint" \
    && mkdir -p /app/data /app/config /app/backups /app/logs /app/scripts /app/update-repository/agent \
    && chmod 755 /app/scripts/repair_storage.py /app/agent/install.sh

EXPOSE 58443

HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 \
    CMD curl -fsS "http://127.0.0.1:${PORT}/health" >/dev/null || exit 1

CMD ["python", "/app/hub_entry.py"]
