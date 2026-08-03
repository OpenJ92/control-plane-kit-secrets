#!/usr/bin/env bash
set -euo pipefail

IMAGE_NAME="${CPK_SECRETS_TEST_IMAGE_NAME:-control-plane-kit-secrets-test:local}"
CONTAINER_NAME="${CPK_SECRETS_TEST_CONTAINER:-cpk-secrets-test-runner}"
POLICY_IMAGE="${CPK_SECRETS_POLICY_IMAGE:-python:3.14-slim}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

cleanup() {
  docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
}

trap cleanup EXIT

cleanup

docker run --rm \
  -v "$ROOT:/source:ro" \
  -v "$ROOT/test_support:/test-support:ro" \
  -e PYTHONDONTWRITEBYTECODE=1 \
  "$POLICY_IMAGE" \
  sh -c 'cd /test-support && python -m unittest discover -s tests -v'

docker run --rm \
  -v "$ROOT:/source:ro" \
  -v "$ROOT/test_support:/test-support:ro" \
  -e PYTHONDONTWRITEBYTECODE=1 \
  "$POLICY_IMAGE" \
  python /test-support/package_integrity.py \
    --package-root /source \
    --source-root src \
    --test-root tests \
    --gate-file test.sh

docker build -f Dockerfile.test --target test -t "$IMAGE_NAME" .
docker run \
  --name "$CONTAINER_NAME" \
  "$IMAGE_NAME" \
  sh -c 'python -m compileall src tests && python -m unittest discover -s tests -v'

docker run --rm \
  "$IMAGE_NAME" \
  sh -c 'cd /tmp && python - <<'"'"'PY'"'"'
import control_plane_kit_secrets

if control_plane_kit_secrets.PACKAGE_NAME != "control-plane-kit-secrets":
    raise SystemExit("unexpected control-plane-kit-secrets package identity")

print("control-plane-kit-secrets import ok")
PY'
