FROM python:3.11-slim@sha256:673719e071ecf27434fd2635bbd8d00f49f4fdd81f243143438a42ced8bedf60

WORKDIR /app

COPY requirements.txt requirements.lock ./
RUN pip install --no-cache-dir -r requirements.txt

COPY *.py .
COPY schemas/ schemas/
COPY strategies/ strategies/

ENV PYTHONUNBUFFERED=1

EXPOSE 8001

CMD ["python", "api.py"]
