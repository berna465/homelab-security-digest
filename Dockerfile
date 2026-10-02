FROM python:3.13-alpine
RUN addgroup -S -g 65532 digest && adduser -S -D -u 65532 -G digest digest
WORKDIR /app
COPY pyproject.toml README.md LICENSE /app/
COPY src /app/src
RUN pip install --no-cache-dir --no-deps .
USER digest
ENTRYPOINT ["homelab-security-digest"]
