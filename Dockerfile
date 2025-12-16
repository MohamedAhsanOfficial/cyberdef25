FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY model.pkl inference.py ./

ENTRYPOINT ["python", "inference.py"]
CMD ["--input", "/input/logs", "--output", "/output/alerts.csv"]
