FROM python:3.11-slim@sha256:673719e071ecf27434fd2635bbd8d00f49f4fdd81f243143438a42ced8bedf60

WORKDIR /app

# Install dependencies first (layer caching — only rebuilds if requirements change)
COPY requirements.txt requirements.lock ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy source
COPY *.py .

EXPOSE 8000 8003

CMD ["python", "redpanda_consumer.py"]
