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
    PYTHONPATH=/usr/src/app \
    HOME=/home/appuser

RUN groupadd --gid 1001 appuser \
    && useradd --uid 1001 --gid appuser --home /home/appuser --create-home --shell /sbin/nologin appuser

WORKDIR /usr/src/app

COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin/gunicorn /usr/local/bin/gunicorn

COPY app.py .
COPY templates/ templates/
COPY static/ static/
COPY features.json .
COPY config.example.json .
COPY docker-entrypoint.sh /usr/local/bin/entrypoint.sh

# /data is the volume mount point for all persistent state
RUN mkdir /data \
    && chown appuser:appuser /data \
    && chown -R appuser:appuser /usr/src/app \
    && chmod +x /usr/local/bin/entrypoint.sh

LABEL org.opencontainers.image.source="https://github.com/RaikyHH/RuleCollector"
LABEL org.opencontainers.image.description="Web viewer for Sigma detection rules"
LABEL org.opencontainers.image.licenses="MIT"

USER appuser

EXPOSE 5000

# All runtime files (sigma_rules.db, config.json, features.json, sync_state/)
# live in /data. The entrypoint seeds defaults on first run without overwriting
# existing files, so user settings survive image updates.
WORKDIR /data

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["gunicorn", "--workers", "4", "--bind", "0.0.0.0:5000", "--chdir", "/usr/src/app", "app:app"]
