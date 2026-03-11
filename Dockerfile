FROM python:3.12-slim

WORKDIR /action

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY scan_pr.py .

ENTRYPOINT ["python", "/action/scan_pr.py"]
