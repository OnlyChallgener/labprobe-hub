FROM python:3.12-slim

ARG HUB_VERSION=dev
LABEL org.opencontainers.image.title="LabProbe Hub" \
      org.opencontainers.image.version="${HUB_VERSION}" \
      org.opencontainers.image.description="LabProbe network monitoring and LabRelay control Hub"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    LABPROBE_HUB_VERSION=${HUB_VERSION} \
    PORT=58443 \
    DATA_DIR=/app/data \
    CONFIG_PATH=/app/config/config.yaml

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates iproute2 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY VERSION /app/VERSION
COPY hub.py /app/hub.py

EXPOSE 58443

CMD ["python", "/app/hub.py"]
