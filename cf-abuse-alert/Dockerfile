FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY *.py webhook_sources.json ./

# /data is where a Northflank volume is mounted for STATE_FILE=/data/state.json
RUN useradd --create-home --uid 1000 runner \
    && mkdir -p /data && chown -R runner:runner /app /data
USER runner

# Health endpoint (/healthz, /readyz), only opened when PORT is set. Keep the port private.
EXPOSE 8080

CMD ["python", "main.py"]
