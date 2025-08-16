#!/usr/bin/env bash
set -euo pipefail
PRJ=${PRJ:-secure-webapp}
REGION=${REGION:-eu-west-1}
aws cloudformation delete-stack --stack-name ${PRJ}-app --region $REGION
aws cloudformation wait stack-delete-complete --stack-name ${PRJ}-app --region $REGION || true
aws cloudformation delete-stack --stack-name ${PRJ}-vpc --region $REGION
aws cloudformation wait stack-delete-complete --stack-name ${PRJ}-vpc --region $REGION || true