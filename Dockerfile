FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY dns_exporter.py .

# Default config — mount your own at runtime:
#   docker run -v $(pwd)/config.yaml:/app/config.yaml ...
COPY config.yaml .

EXPOSE 9253

CMD ["python", "dns_exporter.py", "config.yaml"]
