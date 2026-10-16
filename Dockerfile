FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    THREAT_DB=/app/data/threat.db THREAT_MODEL=/app/models/iforest.joblib \
    THREAT_TRUSTED_NETWORKS=115.249.0.0/16 PORT=8000

WORKDIR /app
COPY requirements.txt .
# pytest/httpx are only needed for tests
RUN pip install --no-cache-dir pandas scikit-learn fastapi uvicorn joblib

COPY src ./src
COPY docker-entrypoint.sh .
RUN useradd --create-home app && mkdir -p data models && chown -R app:app /app \
    && chmod +x docker-entrypoint.sh
USER app

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s \
  CMD python -c "import os,urllib.request;urllib.request.urlopen('http://127.0.0.1:%s/api/health'%os.environ.get('PORT','8000'))"
ENTRYPOINT ["./docker-entrypoint.sh"]
