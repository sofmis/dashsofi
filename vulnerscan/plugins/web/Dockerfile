FROM mcr.microsoft.com/playwright/python:v1.47.0-jammy
WORKDIR /app
COPY web/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY common ./common
COPY web/*.py ./
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
