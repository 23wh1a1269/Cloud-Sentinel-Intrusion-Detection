# AWS deployment guide (EC2 learning setup)

This guide describes a basic deployment path. AWS services may incur charges; check current pricing and use a budget alert before creating resources.

## Architecture
Browser → EC2 instance → Flask application (Docker) → local demo event store.

For a more cloud-native version, replace local JSONL storage with Amazon S3 or DynamoDB and send operational logs to CloudWatch.

## High-level steps
1. Create an AWS account and enable MFA.
2. Set an AWS Budget alert before provisioning resources.
3. Launch a small Amazon Linux or Ubuntu EC2 instance for learning.
4. Configure the security group to allow SSH only from your own IP. For a temporary test, you may allow the app port from your IP only; do not open it to everyone.
5. Connect to the instance using SSH.
6. Install Docker using the official instructions for your chosen OS.
7. Copy this project to the instance (Git clone or secure file transfer).
8. Build and run the container:
   ```bash
   docker build -t cloud-sentinel .
   docker run -d --name cloud-sentinel -p 5000:5000 cloud-sentinel
   ```
9. Browse to `http://EC2-PUBLIC-IP:5000` only for a short, IP-restricted demonstration.
10. Stop and terminate the instance when finished to avoid ongoing charges.

## Before production
- Put the app behind an HTTPS-enabled reverse proxy or load balancer.
- Use Gunicorn or another production WSGI server; do not use Flask's development server.
- Add real authentication and authorization.
- Store secrets in AWS Secrets Manager or Systems Manager Parameter Store.
- Use S3/DynamoDB for durable storage and IAM roles for least-privilege access.
- Enable CloudWatch logging/monitoring and retention policies.
- Apply patching, backups, encryption, rate limiting, and security review.
