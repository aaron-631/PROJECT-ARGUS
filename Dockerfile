FROM python:3.11-slim

WORKDIR /app

COPY requirements.lock .
RUN pip install --no-cache-dir -r requirements.lock

COPY . .

RUN mkdir -p .vault reports

ENTRYPOINT ["python", "argus.py"]
