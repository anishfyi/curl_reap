FROM python:3.12-slim

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY curl_reap ./curl_reap
RUN pip install --no-cache-dir ".[server]" \
    && useradd --system --uid 10001 --home /app reap \
    && chown -R reap:reap /app

USER reap
EXPOSE 8000

ENTRYPOINT ["reap"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8000"]
