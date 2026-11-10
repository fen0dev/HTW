FROM python:3.12-slim
WORKDIR /app
COPY . .
RUN pip install --no-cache-dir -r requirements.txt
USER 1000
CMD ["python", "-m", "service.app"]
