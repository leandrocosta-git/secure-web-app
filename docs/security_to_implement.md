1. Network Security

    Security Groups

        Allow inbound HTTP/HTTPS only from ALB (or your IP if testing)

        Allow SSH from your IP only (and only if absolutely needed)

        Deny all other inbound traffic

    VPC

        Place EC2 instance in private subnet

        Use NAT Gateway for outbound internet access

        No public IP for EC2

    WAF (Web Application Firewall)

        Enable AWS WAF on ALB

        Apply AWS Managed Rules for OWASP Top 10

            SQL injection

            XSS

            Command injection

            Bad bots

2. IAM & Least Privilege

    IAM Role for EC2

        Only allow access to SSM Session Manager and CloudWatch logs

        Deny any S3/EC2/other service access unless explicitly needed

    OIDC for CI/CD

        Use GitHub Actions OIDC to assume a deployment role (no AWS keys in repo)

        Limit role-to-assume with StringEquals conditions for GitHub org/repo/branch

    Block Instance Metadata v1

        Force IMDSv2 for EC2 (HttpTokens=required) to prevent SSRF-based credential theft

3. Application Security

    Flask Config

        Set DEBUG=False in production

        Use strong SECRET_KEY from AWS SSM Parameter Store

        Validate and sanitize all inputs

        Enable HTTPS-only cookies (Secure, HttpOnly, SameSite=Strict)

    Nginx Reverse Proxy

        Redirect all HTTP to HTTPS

        Enable HSTS header (e.g., Strict-Transport-Security: max-age=31536000; includeSubDomains)

        Add CSP, X-Frame-Options, and XSS-Protection headers

4. OS & Patch Management

    Automated Updates

        Enable automatic security updates (Amazon Linux yum-cron)

    Minimal Attack Surface

        Remove unused packages

        Disable password login (SSH key or SSM only)

        Disable root SSH login

    Logging

        Enable system logs in CloudWatch

        Set CloudWatch alarms for high CPU, 5xx errors

5. CI/CD Security

    Pipeline Checks

        Lint & scan code (bandit for Python security checks)

        Run dependency vulnerability scans (pip-audit or safety)

        Fail deployment if vulnerabilities found

    Infrastructure Scanning

        Use cfn-lint and checkov to scan CloudFormation before deploying

6. Monitoring & Incident Response

    CloudTrail

        Enable org-wide logging

    CloudWatch Alarms

        Alert on unusual CPU spikes, request rate anomalies

    GuardDuty

        Enable for threat detection

    SNS

        Set up security alert notifications to your email
