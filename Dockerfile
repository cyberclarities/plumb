# Plumb: WordPress version monitor
# Builds for whatever CPU the host has (Intel/AMD or Apple Silicon/ARM).
FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PLUMB_CONFIG=/config \
    PLUMB_DATA=/data \
    PLUMB_PORT=6443 \
    SITES_FILE=/config/sites.json \
    OUTPUT_DIR=/data/output

# tzdata so TZ= in plumb.env sets the log time zone
RUN apt-get update \
 && apt-get install -y --no-install-recommends tzdata \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

# A fixed, unprivileged user. /data is created here so a new named volume inherits this ownership.
RUN groupadd --system --gid 10001 plumb \
 && useradd --system --uid 10001 --gid plumb --home-dir /nonexistent --shell /usr/sbin/nologin plumb \
 && mkdir -p /data /config \
 && chown plumb:plumb /data

COPY collector.py dashboard_template.html plumb_server.py ./

USER plumb
VOLUME ["/data"]
EXPOSE 6443

# Healthy = the dashboard answers and the data isn't stale. (Self-signed certificate, so no verification here.)
HEALTHCHECK --interval=5m --timeout=10s --start-period=2m --retries=3 \
  CMD python -c "import os,ssl,urllib.request as u; u.urlopen('https://127.0.0.1:'+os.environ.get('PLUMB_PORT','6443')+'/healthz', context=ssl._create_unverified_context(), timeout=8)" || exit 1

ENTRYPOINT ["python", "/app/plumb_server.py"]
CMD ["serve"]
