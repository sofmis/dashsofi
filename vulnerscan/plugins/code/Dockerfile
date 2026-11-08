FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends git curl ca-certificates && rm -rf /var/lib/apt/lists/* \
 && curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
WORKDIR /app
COPY code/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY common ./common
COPY code/app.py .
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
