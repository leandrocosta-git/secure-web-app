#!/usr/bin/env bash
set -euo pipefail

# ---------------------------
# Helper functions
# ---------------------------
need() { command -v "$1" >/dev/null 2>&1 || { echo "Missing dependency: $1" >&2; exit 1; }; }
json() { jq -r "$1"; }
is_tty() { [[ -t 0 && -t 1 ]]; }
ask() { # ask "Prompt" VAR default
  local prompt="$1" var="$2" def="${3:-}"
  if is_tty; then
    local extra=""
    [[ -n "$def" ]] && extra=" [$def]"
    read -r -p "$prompt$extra: " val
    val="${val:-$def}"
    export "$var"="$val"
  else
    # in CI, require it pre-set or defaulted
    : "${!var:=$def}"
    export "$var"
  fi
}

# ---------------------------
# Requirements
# ---------------------------
need aws
need jq

# ---------------------------
# Config (ENV or prompts)
# ---------------------------
ask "AWS profile name"           PROFILE          "${PROFILE:-default}"
ask "AWS region"                 REGION           "${REGION:-eu-west-1}"
ask "Project name"               PROJECT          "${PROJECT:-secure-webapp}"

# Your public /32 for dev access (e.g., to allow you through ALB/SG rules if used)
# You can pre-export DEV_CIDR, or we try auto-detect. Fallback /32 is required.
DEV_CIDR_DEFAULT="${DEV_CIDR:-}"
if [[ -z "${DEV_CIDR_DEFAULT}" ]] && is_tty; then
  # best-effort autodetect
  ME="$(curl -fsS https://checkip.amazonaws.com || true)"
  [[ -n "$ME" ]] && DEV_CIDR_DEFAULT="${ME%$'\n'}/32"
fi
ask "Your public IP in CIDR (/32)" DEV_CIDR "${DEV_CIDR_DEFAULT:-1.2.3.4/32}"

# AZs
ask "AZ A (e.g. eu-west-1a)"     AZA              "${AZA:-${REGION}a}"
ask "AZ B (e.g. eu-west-1b)"     AZB              "${AZB:-${REGION}b}"

# Instance settings
ask "EC2 instance type"          INSTANCE_TYPE    "${INSTANCE_TYPE:-t3.micro}"
ask "AMI ID (AL2 or similar)"    AMI_ID           "${AMI_ID:-ami-0c1bc246476a5572b}"

# Optional ACM cert ARN (empty means HTTP only; listener will 301 when TLS provided)
ask "ACM ARN (leave empty for HTTP only)" ACM_ARN "${ACM_ARN:-}"

# ALB access logs bucket (must exist & have proper policy)
ask "ALB access logs bucket name" ACCESS_LOGS_BUCKET "${ACCESS_LOGS_BUCKET:-secure-webapp-alb-logs}"

# Stack names & templates (override via env if you like)
STACK_VPC="${STACK_VPC:-secure-vpc-dev}"
STACK_ALB="${STACK_ALB:-secure-alb-dev}"
STACK_EC2="${STACK_EC2:-secure-compute-dev}"

VPC_TEMPLATE="${VPC_TEMPLATE:-iac/vpc.yaml}"
ALB_TEMPLATE="${ALB_TEMPLATE:-iac/alb_waf.yaml}"
COMPUTE_TEMPLATE="${COMPUTE_TEMPLATE:-iac/compute.yaml}"

echo "== Using profile=$PROFILE region=$REGION project=$PROJECT =="

# ---------------------------
# 0) Preflight: bucket sanity
# ---------------------------
echo "== preflight: check ALB logs bucket =="
aws s3api head-bucket --bucket "$ACCESS_LOGS_BUCKET" --profile "$PROFILE" --region "$REGION" >/dev/null 2>&1 || {
  echo "ERROR: Bucket '$ACCESS_LOGS_BUCKET' does not exist or is not accessible."
  echo "Create it first (private, versioning optional) and attach the ALB log-delivery policy."
  exit 1
}


### --------------------------
### 1) VPC with NAT
### --------------------------
echo "== deploy: VPC =="
aws cloudformation deploy \
  --template-file "$VPC_TEMPLATE" \
  --stack-name "$STACK_VPC" \
  --parameter-overrides \
    ProjectName="$PROJECT" \
    VpcCidr=10.0.0.0/16 \
    PublicSubnetACidr=10.0.0.0/24 \
    PublicSubnetBCidr=10.0.1.0/24 \
    PrivateSubnetACidr=10.0.10.0/24 \
    PrivateSubnetBCidr=10.0.11.0/24 \
    DevIpCidr="$DEV_CIDR" \
    AllowSshFromDev=true \
    AzA="$AZA" \
    AzB="$AZB" \
  --capabilities CAPABILITY_NAMED_IAM \
  --region "$REGION" --profile "$PROFILE"

VPC_OUT=$(aws cloudformation describe-stacks \
  --stack-name "$STACK_VPC" --region "$REGION" --profile "$PROFILE" \
  --query "Stacks[0].Outputs" --output json)

VPC_ID=$(echo "$VPC_OUT" | json '.[] | select(.OutputKey=="VpcId").OutputValue')
PUBA=$(echo "$VPC_OUT"   | json '.[] | select(.OutputKey=="PublicSubnetAId").OutputValue')
PUBB=$(echo "$VPC_OUT"   | json '.[] | select(.OutputKey=="PublicSubnetBId").OutputValue')
PRIVA=$(echo "$VPC_OUT"  | json '.[] | select(.OutputKey=="PrivateSubnetAId").OutputValue')
PRIVB=$(echo "$VPC_OUT"  | json '.[] | select(.OutputKey=="PrivateSubnetBId").OutputValue')
APP_SG=$(echo "$VPC_OUT" | json '.[] | select(.OutputKey=="AppSgId").OutputValue')
ALB_SG=$(echo "$VPC_OUT" | json '.[] | select(.OutputKey=="AlbSgId").OutputValue')

echo "VPC=$VPC_ID"
echo "PUBA=$PUBA PUBB=$PUBB"
echo "PRIVA=$PRIVA PRIVB=$PRIVB"
echo "APP_SG=$APP_SG ALB_SG=$ALB_SG"

### --------------------------
### 2) ALB + WAF (OWASP managed rules)
### --------------------------

ALB_PARAMS=(
  ProjectName="$PROJECT"
  VpcId="$VPC_ID"
  PublicSubnetAId="$PUBA"
  PublicSubnetBId="$PUBB"
  AppTargetPort=8000
)

# Only pass AcmCertArn if you set it
if [[ -n "${ACM_ARN:-}" ]]; then
  ALB_PARAMS+=(AcmCertArn="$ACM_ARN")
else
  ALB_PARAMS+=(AcmCertArn="")  # safe default
fi


echo "== deploy: ALB + WAF =="
aws cloudformation deploy \
  --template-file "$ALB_TEMPLATE" \
  --stack-name "$STACK_ALB" \
  --parameter-overrides \
    ProjectName="$PROJECT" \
    VpcId="$VPC_ID" \
    PublicSubnetAId="$PUBA" \
    PublicSubnetBId="$PUBB" \
    AppTargetPort=8000 \
    AcmCertArn="$ACM_ARN" \
    AccessLogsBucketName="$ACCESS_LOGS_BUCKET" \
  --capabilities CAPABILITY_NAMED_IAM \
  --region "$REGION" --profile "$PROFILE"

ALB_OUT=$(aws cloudformation describe-stacks \
  --stack-name "$STACK_ALB" --region "$REGION" --profile "$PROFILE" \
  --query "Stacks[0].Outputs" --output json)

TG_ARN=$(echo "$ALB_OUT"  | json '.[] | select(.OutputKey=="AppTargetGroupArn").OutputValue')
ALB_ARN=$(echo "$ALB_OUT" | json '.[] | select(.OutputKey=="AlbArn").OutputValue')
ALB_DNS=$(echo "$ALB_OUT" | json '.[] | select(.OutputKey=="AlbDnsName").OutputValue')

echo "TG=$TG_ARN"
echo "ALB=$ALB_ARN"
echo "DNS=$ALB_DNS"

### --------------------------
### 3) EC2 in PRIVATE subnet (app + logs + SSM)
### --------------------------
echo "== deploy: EC2 (private) =="
aws cloudformation deploy \
  --template-file "$COMPUTE_TEMPLATE" \
  --stack-name "$STACK_EC2" \
  --parameter-overrides \
    ProjectName="$PROJECT" \
    PrivateSubnetId="$PRIVA" \
    AppSecurityGroupId="$APP_SG" \
    AlbSecurityGroupId="$ALB_SG" \
    InstanceType="$INSTANCE_TYPE" \
    AmiId="$AMI_ID" \
    TargetGroupArn="$TG_ARN" \
  --capabilities CAPABILITY_NAMED_IAM \
  --region "$REGION" --profile "$PROFILE"

EC2_OUT=$(aws cloudformation describe-stacks \
  --stack-name "$STACK_EC2" --region "$REGION" --profile "$PROFILE" \
  --query "Stacks[0].Outputs" --output json)

INSTANCE_ID=$(echo "$EC2_OUT" | json '.[] | select(.OutputKey=="InstanceId").OutputValue')
echo "INSTANCE=$INSTANCE_ID"

### --------------------------
### 4) (Optional) Attach instance to TG if not done in template
### --------------------------
# If your compute.yaml ALREADY contains AWS::ElasticLoadBalancingV2::TargetGroupAttachment
# (parameterized by TargetGroupArn), you can skip this section.
#NEEDS_ATTACH="${NEEDS_ATTACH:-auto}"
#if [[ "$NEEDS_ATTACH" == "yes" ]]; then
#  echo "== manual: register-targets =="
#  aws elbv2 register-targets \
#    --target-group-arn "$TG_ARN" \
#    --targets "Id=$INSTANCE_ID" \
#    --region "$REGION" --profile "$PROFILE"
#fi

### --------------------------
### 5) Wait for target healthy & test HTTP
### --------------------------
echo "== wait: target health =="
for i in {1..30}; do
  STATE=$(aws elbv2 describe-target-health \
    --target-group-arn "$TG_ARN" \
    --region "$REGION" --profile "$PROFILE" \
    --query "TargetHealthDescriptions[?Target.Id=='$INSTANCE_ID'].TargetHealth.State" \
    --output text || true)
  echo "  [$i] state=$STATE"
  [[ "$STATE" == "healthy" ]] && break
  sleep 5
done

echo "== test via ALB =="
echo "GET http://$ALB_DNS/health"
curl -fsS "http://$ALB_DNS/health" || true
echo
echo "GET http://$ALB_DNS/"
curl -fsS "http://$ALB_DNS/" || true
echo

### --------------------------
### 6) Sanity: WAF association
### --------------------------
echo "== verify: WAF attached =="
aws wafv2 get-web-acl-for-resource \
  --resource-arn "$ALB_ARN" --scope REGIONAL \
  --region "$REGION" --profile "$PROFILE" \
  --no-cli-pager || true

echo "== done =="
