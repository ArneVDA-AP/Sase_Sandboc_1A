FROM python:3.11-slim
WORKDIR /app
RUN pip install --no-cache-dir pyicap python-docx openpyxl pypdf nats-py==2.14.0 && \
    sed -i 's/import collections/import collections; import collections.abc/' \
        /usr/local/lib/python3.11/site-packages/pyicap.py && \
    sed -i 's/collections\.Callable/collections.abc.Callable/g' \
        /usr/local/lib/python3.11/site-packages/pyicap.py
COPY dlp_icap_server.py .
COPY nats_publisher.py .
EXPOSE 1345
ENV DLP_ICAP_PORT=1345
CMD ["python3", "-u", "dlp_icap_server.py"]
