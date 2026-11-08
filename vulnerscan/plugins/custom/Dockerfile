FROM python:3.12-slim
WORKDIR /app
COPY custom/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY common ./common
COPY custom/app.py .
RUN useradd -m app
USER app
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
