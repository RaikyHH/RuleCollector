FROM python:3.11-slim AS builder

WORKDIR /app

RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt


FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/usr/src/app

RUN adduser --system --group appuser

WORKDIR /usr/src/app

COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin/gunicorn /usr/local/bin/gunicorn

COPY app.py .
COPY templates/ templates/
COPY static/ static/
COPY features.json .

# /data is the volume mount point for sigma_rules.db, config.json, sync_state/
RUN mkdir /data && chown appuser:appuser /data && chown -R appuser:appuser /usr/src/app

LABEL org.opencontainers.image.source="https://github.com/RaikyHH/RuleCollector"
LABEL org.opencontainers.image.description="Web viewer for Sigma detection rules"
LABEL org.opencontainers.image.licenses="MIT"

USER appuser

EXPOSE 5000

# app.py and gunicorn resolve files relative to cwd; run from /data so the
# app finds sigma_rules.db and config.json in the mounted volume.
WORKDIR /data

CMD ["gunicorn", "--workers", "4", "--bind", "0.0.0.0:5000", "--chdir", "/usr/src/app", "app:app"]
