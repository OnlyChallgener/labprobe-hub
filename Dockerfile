FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    DATA_DIR=/app/data \
    CONFIG_PATH=/app/config.yaml \
    PORT=58443

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY hub.py /app/hub.py
COPY config.example.yaml /app/config.example.yaml

EXPOSE 58443

CMD ["python", "/app/hub.py"]
