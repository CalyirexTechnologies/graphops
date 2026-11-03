# Two stages: build the wheel, then install it into a clean runtime that has
# no compiler and no build tooling. The runtime image carries the application
# and its dependencies, nothing else.
FROM python:3.12-slim AS build

WORKDIR /src
COPY pyproject.toml README.md ./
COPY graphops ./graphops

RUN pip install --no-cache-dir build \
    && python -m build --wheel --outdir /dist


FROM python:3.12-slim AS runtime

# Runs as a non-root user with no login shell. A container process that does
# not need to be root should not be root, and this one needs to bind a high
# port and read its own files.
RUN useradd --create-home --shell /usr/sbin/nologin --uid 10001 graphops

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    GRAPHOPS_DB_PATH=/data/graphops.db

COPY --from=build /dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl "fastapi>=0.110" "uvicorn[standard]>=0.27" \
    && rm -f /tmp/*.whl

# The database lives on a volume, not in the image layer.
RUN mkdir -p /data && chown graphops:graphops /data
VOLUME ["/data"]

USER graphops
WORKDIR /home/graphops
EXPOSE 8000

# Readiness, not liveness: it reports unhealthy when the database or the
# estate is missing, so an empty replica is kept out of a load balancer
# rather than answering "no attack paths found".
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request,sys; \
sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health/ready', timeout=4).status==200 else 1)"

# 0.0.0.0 inside a container is the container's own namespace, not the host's.
# Exposure is decided by the port mapping.
CMD ["graphops", "serve", "--host", "0.0.0.0", "--port", "8000"]
