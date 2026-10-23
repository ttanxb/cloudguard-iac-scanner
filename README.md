# CloudGuard – IaC Security Scanner

Scans AWS Terraform code for security misconfigurations **before** deployment (shift-left DevSecOps).

## Rules
| ID | Severity | Check |
|---|---|---|
| CG001 | High | Public S3 bucket |
| CG002 | High | SSH/RDP (22/3389) open to 0.0.0.0/0 |
| CG003 | Medium | Non-web port open to 0.0.0.0/0 |
| CG004 | High | Unencrypted EBS volume |
| CG005 | High | Unencrypted RDS storage |
| CG006 | High | Publicly accessible RDS |
| CG007 | High | Wildcard IAM action |
| CG008 | High | Hard-coded secret |
| CG009 | Low | Missing tags |

Score = 100 - 15 x High - 8 x Medium - 3 x Low.

## Run
```
pip install -r requirements.txt
pytest -v
python run.py          # http://localhost:8000
docker build -t cloudguard . && docker run -d -p 8000:8000 cloudguard
```
Stack: Python, Flask, pytest, Docker, GitHub Actions, Render.
