# syntax=docker/dockerfile:1.7
FROM python:3.12-slim-bookworm AS builder

ENV VIRTUAL_ENV=/opt/venv \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1
RUN python -m venv "$VIRTUAL_ENV"
ENV PATH="$VIRTUAL_ENV/bin:$PATH"
WORKDIR /build
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --upgrade pip && pip install .

FROM python:3.12-slim-bookworm AS runtime

ENV VIRTUAL_ENV=/opt/venv \
    PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1
COPY --from=builder /opt/venv /opt/venv
RUN groupadd --gid 65532 telemetry \
    && useradd --uid 65532 --gid telemetry --no-create-home --shell /usr/sbin/nologin telemetry \
    && mkdir -p /data/output \
    && chown -R telemetry:telemetry /data
USER 65532:65532
WORKDIR /data
EXPOSE 9108
HEALTHCHECK --interval=20s --timeout=3s --start-period=10s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:9108/metrics', timeout=2)"]
ENTRYPOINT ["ids-telemetry"]
CMD ["run"]
