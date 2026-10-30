# Cloud Sentinel — Cloud-Based Intrusion Detection System

A beginner-friendly cloud computing + cybersecurity project. It provides a Flask dashboard that accepts simulated web security events, applies transparent detection rules, and displays alerts.

## Features
- Dashboard with HIGH / MEDIUM / LOW event counts.
- Manual event submission and CSV import.
- Rule-based detection for SQL-injection-like strings, path traversal, scanner tool names, and HTTP 401/403 events.
- Local JSONL event storage for easy setup.
- Dockerfile for containerization.
- AWS deployment guide in `docs/AWS_DEPLOYMENT.md`.

## Requirements
- Python 3.10 or newer
- pip
- Optional: Docker

## Run locally (Linux / macOS)
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```
Open http://127.0.0.1:5000 and click **Load demo data**.

## Run locally (Windows)
```powershell
py -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

## Docker
```bash
docker build -t cloud-sentinel .
docker run --rm -p 5000:5000 cloud-sentinel
```
Note: this demo writes event history inside the container. For persistent deployment, attach a persistent volume or configure managed storage.

## CSV format
CSV must contain these columns: `source_ip,path,status,message,user_agent`. A sample is in `static/sample_events.csv`.

## Cloud computing concepts demonstrated
1. Cloud-hosted web application.
2. Containerization with Docker.
3. Separation of application and storage layers (ready to extend to managed storage).
4. Centralized event collection and monitoring concepts.
5. Deployment to a cloud virtual machine (AWS EC2 guide).

## Important limitations
This is an educational prototype, not a production SIEM or a validated IDS. Detection is rule-based and may produce false positives/negatives. Do not expose the development server directly to the public internet. Before real deployment, use a production WSGI server, HTTPS, authentication/authorization, input validation, managed secrets, persistent database/object storage, rate limiting, audit logging, and security testing. Only ingest logs you are authorized to process.

## Suggested extensions
- Store events in PostgreSQL or DynamoDB.
- Send alerts through email/SNS.
- Add authentication and role-based access.
- Add CloudWatch metrics/logs.
- Add a trained anomaly-detection model using a properly labeled dataset.
