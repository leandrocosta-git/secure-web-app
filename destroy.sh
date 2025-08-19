#!/usr/bin/env bash
set -euo pipefail

# ---- config (change if yours differ) ----
export AWS_PROFILE="${AWS_PROFILE:-cloudsec-deployer}"
export AWS_REGION="${AWS_REGION:-eu-west-1}"

ALB_STACK="secure-alb-dev"
EC2_STACK="secure-compute-dev"
VPC_STACK="secure-vpc-dev"

LOGS_BUCKET="secure-webapp-alb-logs"
ARTIFACT_BUCKET="secure-webapp-artifacts-eu-west-1"

PROJECT_TAG="secure-webapp"
PRJ=${PRJ:-secure-webapp}

# ---- helpers ----
have() { command -v "$1" >/dev/null 2>&1; }
have aws || { echo "aws cli required"; exit 1; }

echo "== identity =="
aws sts get-caller-identity

echo "== STOP any running EC2 with Project tag (optional, stacks should handle) =="
IDS=$(aws ec2 describe-instances \
  --filters "Name=tag:Project,Values=${PROJECT_TAG}" "Name=instance-state-name,Values=running" \
  --query "Reservations[].Instances[].InstanceId" --output text || true)
if [[ -n "${IDS}" ]]; then
  echo "Terminating: ${IDS}"
  aws ec2 terminate-instances --instance-ids ${IDS} >/dev/null
else
  echo "No running instances with tag Project=${PROJECT_TAG}"
fi

echo "== DELETE ALB/WAF stack (if exists) =="
if aws cloudformation describe-stacks --stack-name "$ALB_STACK" >/dev/null 2>&1; then
  aws cloudformation delete-stack --stack-name "$ALB_STACK"
  aws cloudformation wait stack-delete-complete --stack-name "$ALB_STACK"
  echo "Deleted $ALB_STACK"
else
  echo "Stack $ALB_STACK not found (ok)"
fi

echo "== DELETE compute stack (if exists) =="
if aws cloudformation describe-stacks --stack-name "$EC2_STACK" >/dev/null 2>&1; then
  aws cloudformation delete-stack --stack-name "$EC2_STACK"
  aws cloudformation wait stack-delete-complete --stack-name "$EC2_STACK"
  echo "Deleted $EC2_STACK"
else
  echo "Stack $EC2_STACK not found (ok)"
fi

echo "== EMPTY & DELETE S3 buckets (logs, artifacts) =="

# logs bucket (ALB access logs)
if aws s3api head-bucket --bucket "$LOGS_BUCKET" >/dev/null 2>&1; then
  echo "Emptying $LOGS_BUCKET ..."
  aws s3 rm "s3://${LOGS_BUCKET}" --recursive || true
  # If versioning was on, purge versions too:
  if aws s3api get-bucket-versioning --bucket "$LOGS_BUCKET" --query 'Status' --output text 2>/dev/null | grep -q Enabled; then
    VERS=$(aws s3api list-object-versions --bucket "$LOGS_BUCKET" \
      --query '{Objects: Versions[].{Key:Key,VersionId:VersionId}, DeleteMarkers: DeleteMarkers[].{Key:Key,VersionId:VersionId}}' \
      --output json)
    echo "$VERS" | jq -c '.Objects[]?, .DeleteMarkers[]?' | while read -r obj; do
      KEY=$(echo "$obj" | jq -r '.Key'); VID=$(echo "$obj" | jq -r '.VersionId')
      aws s3api delete-object --bucket "$LOGS_BUCKET" --key "$KEY" --version-id "$VID" || true
    done
  fi
  aws s3 rb "s3://${LOGS_BUCKET}" || true
else
  echo "Bucket $LOGS_BUCKET not found (ok)"
fi

# artifact bucket (pipeline uploads)
if aws s3api head-bucket --bucket "$ARTIFACT_BUCKET" >/dev/null 2>&1; then
  echo "Emptying $ARTIFACT_BUCKET ..."
  aws s3 rm "s3://${ARTIFACT_BUCKET}" --recursive || true
  aws s3 rb "s3://${ARTIFACT_BUCKET}" || true
else
  echo "Bucket $ARTIFACT_BUCKET not found (ok)"
fi

echo "== DELETE VPC stack (removes NAT Gateway/EIP/IGW etc.) =="
if aws cloudformation describe-stacks --stack-name "$VPC_STACK" >/dev/null 2>&1; then
  aws cloudformation delete-stack --stack-name "$VPC_STACK"
  aws cloudformation wait stack-delete-complete --stack-name "$VPC_STACK"
  echo "Deleted $VPC_STACK"
else
  echo "Stack $VPC_STACK not found (ok)"
fi

echo "== VERIFY nothing expensive remains =="

echo "-- NAT Gateways --"
aws ec2 describe-nat-gateways --filter Name=state,Values=available \
  --query "NatGateways[].NatGatewayId" --output text || true

echo "-- Load Balancers --"
aws elbv2 describe-load-balancers --query "LoadBalancers[].LoadBalancerArn" --output text || true

echo "-- EC2 still running with tag --"
aws ec2 describe-instances \
  --filters "Name=tag:Project,Values=${PROJECT_TAG}" "Name=instance-state-name,Values=running" \
  --query "Reservations[].Instances[].InstanceId" --output text || true

echo "-- EIPs (released?) --"
aws ec2 describe-addresses --query "Addresses[].AllocationId" --output text || true

echo "-- WAF WebACL associations --"
aws wafv2 list-web-acls --scope REGIONAL --query "WebACLs[].Name" --output text || true

aws cloudformation delete-stack --stack-name ${PRJ}-app --region $AWS_REGION
aws cloudformation wait stack-delete-complete --stack-name ${PRJ}-app --region $AWS_REGION || true
aws cloudformation delete-stack --stack-name ${PRJ}-vpc --region $AWS_REGION
aws cloudformation wait stack-delete-complete --stack-name ${PRJ}-vpc --region $AWS_REGION || true

# ---- checks ----

# EC2 instances
aws ec2 describe-instances --filters Name=instance-state-name,Values=running --query "Reservations[].Instances[].InstanceId"
# NAT Gateways
aws ec2 describe-nat-gateways --query "NatGateways[].NatGatewayId"
# Elastic IPs
aws ec2 describe-addresses --query "Addresses[].AllocationId"
# Load Balancers
aws elbv2 describe-load-balancers --query "LoadBalancers[].LoadBalancerArn"
# WAF WebACLs
aws wafv2 list-web-acls --scope REGIONAL --query "WebACLs[].Name"
# S3 buckets you used
aws s3 ls | grep -E 'secure-webapp-artifacts|secure-webapp-alb-logs'


echo "== DONE =="
