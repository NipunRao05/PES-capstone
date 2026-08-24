FROM python:3.11-slim

WORKDIR /app

# Install dependencies first (layer caching — only rebuilds if requirements change)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source
COPY *.py .

EXPOSE 8000 8003

CMD ["python", "redpanda_consumer.py"]
