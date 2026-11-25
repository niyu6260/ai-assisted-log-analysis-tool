FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
COPY pyproject.toml README.md ./
COPY charger_log_diag ./charger_log_diag
COPY ccu_log_diag ./ccu_log_diag
COPY charger_log_cloud ./charger_log_cloud
COPY rules ./rules
COPY knowledge ./knowledge

RUN pip install --no-cache-dir ".[cloud]"

EXPOSE 8080
CMD ["uvicorn", "charger_log_cloud.app:app", "--host", "0.0.0.0", "--port", "8080"]
