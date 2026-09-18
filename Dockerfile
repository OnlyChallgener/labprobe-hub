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

# Every root-level Hub module ships together.
#
# This used to be a hand-maintained allowlist of individual COPY lines.  That
# allowlist silently omitted child_guard_service.py, which hub.py imports at
# module scope, so the container died on `import hub` and Docker restarted it
# forever.  A glob cannot drift away from the repository, so adding a new
# root-level module no longer requires touching this file.
COPY *.py /app/
COPY scripts/labprobe-install.sh /app/agent/install.sh
COPY router /app/router
COPY assistant /app/assistant
COPY router_core /app/router_core
COPY scripts/repair_storage.py /app/scripts/repair_storage.py
COPY scripts/docker_preflight.py /app/scripts/docker_preflight.py

# Compile every module that ended up in the image instead of a hand-written
# list, so a syntax error anywhere fails the build rather than the container.
RUN python -m compileall -q /app \
    && find /app -type d -name __pycache__ -prune -exec rm -rf {} +

# Import smoke test for the modules that are safe to import standalone.
#
# hub.py and hub_entry.py cannot be imported here because importing them starts
# the server, so they are covered by the compileall pass above and by the
# preflight check below.  child_guard_service is listed explicitly because its
# absence from this list is exactly what let the missing COPY ship.
RUN python -c "import child_guard_service, rdpi_signature_service, labprobe_storage, hub0934_fixes, hub0935_sync_fix, followup_stability_patch, final_stability_patch, labrelay_sync_patch, lab_ddns, lab_ddns_providers, agent_presence_patch, device_history_patch, portmap_persistence_patch, portmap_firewall, stun_port_config_patch, tcp_session_service, usage_aggregate, router_lite_realtime_patch, router_device_live_sync_patch, router_fast_watchdog_patch, router_build024_fix, router_slow_cache_patch, router_control_scheduler_patch, router_control_actor_patch, router_task_manager_patch, router_config_sync_patch, ipv6_neighbor_archive_patch, router.ipv6, hub_realtime_ws, assistant, router_core, router_core.driver.reyee_session, router_core.driver.reyee_rpc, router_core.driver.reyee, router_core.cache.router_cache, router_core.realtime.router_realtime, router_core.service.router_service, router_core.service.blueprint" \
    && mkdir -p /app/data /app/config /app/backups /app/logs /app/scripts /app/update-repository/agent \
    && chmod 755 /app/scripts/repair_storage.py /app/agent/install.sh

# Final guard: resolve every top-level import reachable from the real entry
# points.  Compiling /app does not catch a missing file, but this does -- it is
# the check that would have failed the build for the crash-looping image.
RUN python /app/scripts/docker_preflight.py /app

EXPOSE 58443

HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 \
    CMD curl -fsS "http://127.0.0.1:${PORT}/health" >/dev/null || exit 1

CMD ["python", "/app/hub_entry.py"]
