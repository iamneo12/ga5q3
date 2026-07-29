
FROM python:3.12-slim
 
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
 
COPY guardrail_server.py .
 
EXPOSE 8080
CMD ["gunicorn", "guardrail_server:app", "--bind", "0.0.0.0:8080"]
