FROM python:3.11-slim

COPY examples/mssql/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY injectify ./injectify
COPY examples/mssql/main.py .

EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
