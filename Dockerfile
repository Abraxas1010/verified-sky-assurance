FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

WORKDIR /app

COPY assurance/ assurance/
COPY python/ python/
COPY examples/ examples/

RUN useradd --create-home --shell /bin/bash appuser \
    && chown -R appuser:appuser /app

USER appuser

ENTRYPOINT ["python3", "python/verify_attestation.py"]
CMD ["examples/attestation.json", "examples/bundle.json", "examples/results.json"]
