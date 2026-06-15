#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<EOF
Usage: $(basename "$0") [options]

Deploy the vcknots AWS CDK stack (ResourcesStack).

Options:
  -p, --profile PROFILE   AWS profile to use (optional).
  -s, --stage STAGE       API Gateway stage name (default: test).
  -h, --help              Show this help.

Configuration:
  Loads server/aws/resources/scripts/.env when present (if it exists).
  CLI options override .env and existing environment variables.

Environment:
  AWS_PROFILE   AWS profile (used when --profile is omitted).
  API_STAGE     API Gateway stage (default: test).
  STACK_NAME    CloudFormation stack name (default: ResourcesStack).
EOF
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESOURCES_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

if [[ -f "${SCRIPT_DIR}/.env" ]]; then
  set -a
  # shellcheck source=/dev/null
  source "${SCRIPT_DIR}/.env"
  set +a
fi

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)
      usage
      exit 0
      ;;
    -p|--profile)
      if [[ $# -lt 2 ]]; then
        echo "Error: --profile requires a value" >&2
        exit 1
      fi
      AWS_PROFILE="$2"
      shift 2
      ;;
    -s|--stage)
      if [[ $# -lt 2 ]]; then
        echo "Error: --stage requires a value" >&2
        exit 1
      fi
      API_STAGE="$2"
      shift 2
      ;;
    *)
      echo "Error: unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [[ -n "${AWS_PROFILE:-}" ]]; then
  export AWS_PROFILE
fi

export API_STAGE="${API_STAGE:-test}"
STACK_NAME="${STACK_NAME:-ResourcesStack}"

cd "${RESOURCES_DIR}"

echo "==> AWS profile: ${AWS_PROFILE:-default}"
echo "==> API stage: ${API_STAGE}"
echo "==> Stack: ${STACK_NAME}"
echo "==> Working directory: ${RESOURCES_DIR}"

ACCOUNT_ID="$(aws sts get-caller-identity --query Account --output text)"
REGION="$(aws configure get region || true)"
if [[ -z "${REGION}" ]]; then
  REGION="${AWS_DEFAULT_REGION:-ap-northeast-1}"
fi

export CDK_DEFAULT_ACCOUNT="${ACCOUNT_ID}"
export CDK_DEFAULT_REGION="${REGION}"

aws sts get-caller-identity

echo "==> CDK account: ${CDK_DEFAULT_ACCOUNT}"
echo "==> CDK region: ${CDK_DEFAULT_REGION}"

echo "==> CDK bootstrap (no-op if already bootstrapped)"
pnpm cdk bootstrap

echo "==> CDK deploy"
pnpm cdk deploy "${STACK_NAME}" --require-approval never
