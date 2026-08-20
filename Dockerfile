FROM python:3.12-slim

RUN useradd --create-home --uid 10001 exporter
WORKDIR /app
COPY --chown=exporter:exporter exporter.py /app/exporter.py
COPY --chown=exporter:exporter callback_watcher.py /app/callback_watcher.py
USER exporter

ENV PORT=8080 \
    NFS_EXPORT_DIR=/exports \
    ELASTICSEARCH_PAGE_SIZE=5000 \
    ELASTICSEARCH_PIT_KEEP_ALIVE=1h \
    MAX_RECORDS=0 \
    EXPORT_PAGE_DELAY_SECONDS=0.5 \
    ELASTICSEARCH_RETRY_ATTEMPTS=6 \
    ELASTICSEARCH_RETRY_INITIAL_SECONDS=1 \
    ELASTICSEARCH_RETRY_MAX_SECONDS=30 \
    CALCULATE_TOTAL_HITS=true \
    PROGRESS_MANIFEST_EVERY_PAGES=5 \
    CSV_ROWS_PER_FILE=200000 \
    CSV_SAFE_FOR_SPREADSHEETS=true

EXPOSE 8080
ENTRYPOINT ["python", "/app/exporter.py"]
