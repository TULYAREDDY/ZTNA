FROM python:3.12-slim

WORKDIR /srv
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY ztna_proxy.py .

ENV ZTNA_PDP_URL=http://backend:8000/api/access \
    ZTNA_LISTEN=0.0.0.0:9090

EXPOSE 9090
CMD ["python", "ztna_proxy.py"]
