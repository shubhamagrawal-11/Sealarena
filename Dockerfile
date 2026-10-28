# Multi-purpose lightweight service container for SealArena (Render & Cloud Production Ready)
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PORT=8080

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    iproute2 \
    iptables \
    net-tools \
    dnsutils \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

RUN groupadd -g 1000 sealgroup && \
    useradd -u 1000 -g sealgroup -s /bin/bash -m sealuser

COPY src /app/src
COPY configs /app/configs
COPY certs /app/certs
COPY data /app/data
COPY cli /app/cli
COPY leaktest /app/leaktest
COPY demo.py /app/demo.py

RUN chown -R sealuser:sealgroup /app

USER 1000:1000

ENV PYTHONPATH=/app

EXPOSE 8080

CMD ["sh", "-c", "uvicorn src.dashboard.main:app --host 0.0.0.0 --port ${PORT:-8080}"]
