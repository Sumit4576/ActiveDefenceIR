# Backend image: mock target server (main.py) + WebSocket bridge (ws_server.py)
FROM python:3.14-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY *.py ./
COPY honeypots/ ./honeypots/

RUN useradd --create-home --uid 10001 appuser && chown -R appuser /app
USER appuser

EXPOSE 8000 8765

# Default: the mock target server. docker-compose overrides this for the WS bridge.
CMD ["python", "main.py"]
