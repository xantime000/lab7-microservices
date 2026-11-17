FROM python:3.10-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY order_service/ ./order_service/

ENV PYTHONPATH=/app
ENV PORT=8003

EXPOSE 8003

CMD ["uvicorn", "order_service.app:app", "--host", "0.0.0.0", "--port", "8003"]
