FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONPATH=/app

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY api ./api
COPY lab ./lab
COPY src ./src
COPY docs ./docs
COPY PRD.md README.md ./

RUN mkdir -p data/raw data/processed data/logs data/evidence/exports data/evidence/screenshots models

EXPOSE 8000 5000

CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]
