#!/usr/bin/env bash
set -euo pipefail

IMAGE_NAME="${CPK_SECRETS_TEST_IMAGE_NAME:-control-plane-kit-secrets-test:local}"
CONTAINER_NAME="${CPK_SECRETS_TEST_CONTAINER:-cpk-secrets-test-runner}"

cleanup() {
  docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
}

trap cleanup EXIT

cleanup

docker build -f Dockerfile.test --target test -t "$IMAGE_NAME" .
docker run \
  --name "$CONTAINER_NAME" \
  "$IMAGE_NAME" \
  sh -c 'python -m compileall src tests && python -m unittest discover -s tests -v'
