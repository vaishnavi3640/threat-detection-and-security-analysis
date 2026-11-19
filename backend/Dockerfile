FROM python:3.11-slim
WORKDIR /app
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY backend/ ./backend/
COPY threatguard/ ./threatguard/
ENV PYTHONPATH=/app/threatguard
EXPOSE 5000
CMD ["python", "backend/run.py"]
