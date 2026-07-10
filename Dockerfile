# syntax=docker/dockerfile:1

FROM python:3.14-slim AS builder
WORKDIR /build
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir --upgrade pip build && python -m build --wheel

FROM python:3.14-slim AS runtime
LABEL org.opencontainers.image.source="https://github.com/yourname/ioc-extractor"
LABEL org.opencontainers.image.description="Extract, validate, and normalize Indicators of Compromise from text."
LABEL org.opencontainers.image.licenses="MIT"

RUN useradd --create-home --uid 1000 analyst
WORKDIR /home/analyst

COPY --from=builder /build/dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm -rf /tmp/*.whl

USER analyst
ENTRYPOINT ["ioc-extractor"]
CMD []
