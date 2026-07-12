FROM python:3.12-slim

WORKDIR /srv

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY app ./app
COPY start-backend.sh ./start-backend.sh
RUN chmod +x ./start-backend.sh

EXPOSE 8000
CMD ["./start-backend.sh"]
