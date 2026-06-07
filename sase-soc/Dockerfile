FROM python:3.12-slim
WORKDIR /app
RUN pip install --no-cache-dir --upgrade pip
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app/ ./app/
COPY web/ ./web/
RUN mkdir -p /data
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8090", \
     "--log-level", "info", "--no-access-log"]
