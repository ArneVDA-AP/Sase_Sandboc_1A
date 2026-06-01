FROM python:3.12-slim
RUN pip install --no-cache-dir nats-py==2.14.0
COPY forwarder.py /app/forwarder.py
WORKDIR /app
CMD ["python3", "-u", "forwarder.py"]
