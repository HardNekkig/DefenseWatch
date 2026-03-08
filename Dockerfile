FROM python:3.12-slim AS base

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY defensewatch/ defensewatch/
COPY static/ static/
COPY config.yaml .

RUN mkdir -p data

EXPOSE 9000

CMD ["uvicorn", "defensewatch.main:app", "--host", "0.0.0.0", "--port", "9000"]
