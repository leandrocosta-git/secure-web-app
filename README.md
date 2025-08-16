# Web App on AWS

### Secure Web App (EC2 Private) + ALB + WAF + OIDC CI/CD

![AWS](https://img.shields.io/badge/AWS-EC2%2C%20ALB%2C%20WAF%2C%20Secrets%20Manager-orange)
![Made with IaC](https://img.shields.io/badge/IaC-CloudFormation-informational)

**Goal:** Production-style, **secure-by-default** web app on AWS:
- Private EC2 (no SSH), ALB + **WAF** (Core/SQLi/XSS), TLS 1.2+, **HSTS**
- Secrets in **AWS Secrets Manager**, optional **RDS** in private subnets
- Observability with CloudWatch + Alarms
- **GitHub Actions OIDC** deployment (no long-lived keys)
- Guardrails: **cfn-lint**, **cfn-guard**, least-privilege IAM

📄 [Read the full report](./docs/report.md)

<details>

## Architecture

![Architecture](./docs/images/architecture.png)

**Key controls**
- Zero SSH; access via **SSM Session Manager** only
- ALB in public subnets; instances in private subnets
- WAF managed rules + rate limiting
- IMDSv2 enforced, EBS/RDS/S3 encryption at rest
- Security headers (HSTS, CSP, XFO, XCTO)
</details>
