FROM python:3.12-slim
WORKDIR /srv
COPY orchestrator/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY orchestrator/app ./app
COPY frontend ./frontend
RUN useradd -m app && chown -R app /srv
USER app
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
