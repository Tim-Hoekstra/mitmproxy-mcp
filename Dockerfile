FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libpq-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY pyproject.toml .
COPY src/ src/
COPY migrations/ migrations/

RUN pip install --no-cache-dir .

EXPOSE 8080

ENTRYPOINT ["python", "-m", "mitmproxy_mcp"]
