FROM python:3.12-slim

ARG APP_VERSION=dev
ARG BUILD_TIME=unknown
ARG REPO_URL=unknown

LABEL org.opencontainers.image.title="cf-ip-optimizer" \
      org.opencontainers.image.description="Cloudflare 优选 IP 自动扫描与 DNS 解析更新" \
      org.opencontainers.image.revision="${APP_VERSION}" \
      org.opencontainers.image.created="${BUILD_TIME}" \
      org.opencontainers.image.source="${REPO_URL}"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    TZ=Asia/Shanghai \
    DATA_DIR=/data \
    DB_PATH=/data/app.db \
    APP_VERSION=${APP_VERSION}

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY docker-entrypoint.py /entrypoint.py

RUN chmod +x /entrypoint.py \
    && useradd -u 1000 -m appuser \
    && mkdir -p /data \
    && chown -R appuser:appuser /data /app

# 不写 USER：入口脚本需要 root 权限修正 bind mount 目录属主，
# 修正完会自己降权到 PUID:PGID（默认 1000:1000）再启动服务。
VOLUME ["/data"]
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=4).status==200 else 1)"

ENTRYPOINT ["python", "/entrypoint.py"]
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080", "--no-access-log"]
