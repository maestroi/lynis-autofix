#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ -f "${ROOT_DIR}/scripts/e2e-remote.env.local" ]]; then
  # shellcheck disable=SC1091
  source "${ROOT_DIR}/scripts/e2e-remote.env.local"
fi

HOST="${HARDENER_E2E_HOST:-maestro@192.168.50.13}"
REMOTE_DIR="${HARDENER_E2E_REMOTE_DIR:-/tmp/hardener-e2e}"
REMOTE_TEST_CMD="${HARDENER_E2E_REMOTE_TEST_CMD:-sudo HARDENER_INTEGRATION=1 go test -tags integration ./e2e/... -v}"
SSH_OPTS="${HARDENER_E2E_SSH_OPTS:-}"

if ! command -v ssh >/dev/null 2>&1; then
  echo "ssh is required but not found." >&2
  exit 1
fi
if ! command -v rsync >/dev/null 2>&1; then
  echo "rsync is required but not found." >&2
  exit 1
fi

echo "Syncing repository to ${HOST}:${REMOTE_DIR}"
rsync_cmd=(
  rsync -az --delete
  --exclude ".git"
  --exclude "hardener"
  --exclude ".codex"
  --exclude "scripts/e2e-remote.env.local"
)
if [[ -n "${SSH_OPTS}" ]]; then
  rsync_cmd+=(-e "ssh ${SSH_OPTS}")
fi
rsync_cmd+=("${ROOT_DIR}/" "${HOST}:${REMOTE_DIR}/")
"${rsync_cmd[@]}"

echo "Running remote integration tests on ${HOST}"
ssh_cmd=(ssh)
if [[ -n "${SSH_OPTS}" ]]; then
  # Intentionally split on spaces so users can provide standard ssh options.
  read -r -a ssh_opts_array <<<"${SSH_OPTS}"
  ssh_cmd+=("${ssh_opts_array[@]}")
fi
ssh_cmd+=("${HOST}" "set -euo pipefail; cd '${REMOTE_DIR}'; ${REMOTE_TEST_CMD}")
"${ssh_cmd[@]}"
