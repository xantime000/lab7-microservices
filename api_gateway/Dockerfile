FROM python:3.10-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY api_gateway/ ./api_gateway/

ENV PYTHONPATH=/app
ENV PORT=8000

EXPOSE 8000

CMD ["uvicorn", "api_gateway.app:app", "--host", "0.0.0.0", "--port", "8000"]
