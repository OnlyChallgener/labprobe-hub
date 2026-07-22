FROM python:3.12-slim-bookworm

ARG TARGETARCH
ARG GECKODRIVER_VERSION=0.36.0

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=4445 \
    BIND_HOST=0.0.0.0 \
    LOGS_DIR=/app/logs \
    ROUTER_BROWSER_HEADLESS=true \
    MOZ_HEADLESS=1 \
    MOZ_DISABLE_CONTENT_SANDBOX=1

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        firefox-esr \
    && case "${TARGETARCH}" in \
         amd64) GECKO_ARCH="linux64" ;; \
         arm64) GECKO_ARCH="linux-aarch64" ;; \
         *) echo "Unsupported TARGETARCH=${TARGETARCH}" >&2; exit 1 ;; \
       esac \
    && curl -fsSL \
         "https://github.com/mozilla/geckodriver/releases/download/v${GECKODRIVER_VERSION}/geckodriver-v${GECKODRIVER_VERSION}-${GECKO_ARCH}.tar.gz" \
       | tar -xz -C /usr/local/bin geckodriver \
    && chmod 755 /usr/local/bin/geckodriver \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt \
    && rm -rf /root/.cache/pip

COPY app.py /app/app.py
RUN python -m py_compile /app/app.py \
    && mkdir -p /app/logs

EXPOSE 4445

HEALTHCHECK --interval=20s --timeout=5s --start-period=30s --retries=5 \
    CMD curl -fsS "http://127.0.0.1:${PORT}/health" >/dev/null || exit 1

CMD ["/bin/sh", "-ec", "exec gunicorn --bind ${BIND_HOST:-0.0.0.0}:${PORT:-4445} --workers 1 --threads 4 --timeout 240 --access-logfile - --error-logfile - app:app"]
