#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ -f "${ROOT_DIR}/scripts/prod-remote.env.local" ]]; then
  # shellcheck disable=SC1091
  source "${ROOT_DIR}/scripts/prod-remote.env.local"
fi

HOST="${HARDENER_PROD_HOST:-root@192.168.50.13}"
SSH_OPTS="${HARDENER_PROD_SSH_OPTS:-}"
REMOTE_WORKDIR="${HARDENER_PROD_REMOTE_WORKDIR:-/opt/hardener}"
STATE_DIR="${HARDENER_PROD_STATE_DIR:-/var/lib/hardener}"
PROFILE="${HARDENER_PROD_PROFILE:-server}"
OUTPUT="${HARDENER_PROD_OUTPUT:-table}"
REPORT_PATH="${HARDENER_PROD_REPORT_PATH:-/var/log/lynis-report.dat}"
LYNIS_CMD="${HARDENER_PROD_LYNIS_CMD:-lynis audit system --quick}"
LYNIS_ENSURE="${HARDENER_PROD_LYNIS_ENSURE:-package}"
LYNIS_VERSION="${HARDENER_PROD_LYNIS_VERSION:-3.1.6}"
APPLY="${HARDENER_PROD_APPLY:-0}"
CONFIRM_DANGEROUS="${HARDENER_PROD_CONFIRM_DANGEROUS:-0}"
ROLLBACK_RUN_ID="${HARDENER_PROD_ROLLBACK_RUN_ID:-}"
SUDO_CMD="${HARDENER_PROD_SUDO:-sudo}"

LOCAL_BINARY="${ROOT_DIR}/hardener"

if ! command -v ssh >/dev/null 2>&1; then
  echo "ssh is required but not found." >&2
  exit 1
fi
if ! command -v rsync >/dev/null 2>&1; then
  echo "rsync is required but not found." >&2
  exit 1
fi
if ! command -v go >/dev/null 2>&1; then
  echo "go is required locally to build the hardener binary." >&2
  exit 1
fi

ssh_cmd=(ssh)
if [[ -n "${SSH_OPTS}" ]]; then
  read -r -a ssh_opts_array <<<"${SSH_OPTS}"
  ssh_cmd+=("${ssh_opts_array[@]}")
fi
ssh_cmd+=("${HOST}")

echo "Building Linux binary locally"
(
  cd "${ROOT_DIR}"
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o "${LOCAL_BINARY}" .
)

echo "Preparing remote directories on ${HOST}"
"${ssh_cmd[@]}" "${SUDO_CMD} mkdir -p '${REMOTE_WORKDIR}' '${STATE_DIR}' '${STATE_DIR}/runs' '${STATE_DIR}/backups' '${STATE_DIR}/locks'"

ensure_lynis_remote() {
  case "${LYNIS_ENSURE}" in
    skip)
      echo "Skipping Lynis installation/version enforcement"
      ;;
    package)
      echo "Ensuring Lynis package is installed"
      "${ssh_cmd[@]}" "${SUDO_CMD} bash -lc 'command -v lynis >/dev/null 2>&1 || (apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y lynis)'"
      ;;
    latest)
      echo "Ensuring Lynis ${LYNIS_VERSION} is installed from upstream"
      "${ssh_cmd[@]}" "${SUDO_CMD} bash -lc '
set -euo pipefail
current=\"\$(lynis show version 2>/dev/null || true)\"
if [[ \"\${current}\" == \"${LYNIS_VERSION}\" ]]; then
  exit 0
fi
tmp_tgz=\"/tmp/lynis-${LYNIS_VERSION}.tar.gz\"
install_dir=\"/opt/lynis-${LYNIS_VERSION}\"
curl --fail --location --silent --show-error --compressed \
  \"https://downloads.cisofy.com/lynis/lynis-${LYNIS_VERSION}.tar.gz\" \
  -o \"\${tmp_tgz}\"
mkdir -p \"\${install_dir}\"
tar -xzf \"\${tmp_tgz}\" --strip-components=1 -C \"\${install_dir}\"
chmod 0755 \"\${install_dir}/lynis\"
ln -sf \"\${install_dir}/lynis\" /usr/local/bin/lynis
'"
      ;;
    *)
      echo "Invalid HARDENER_PROD_LYNIS_ENSURE value: ${LYNIS_ENSURE}" >&2
      echo "Valid values: package, latest, skip" >&2
      exit 1
      ;;
  esac
}

ensure_lynis_remote

echo "Uploading hardener binary"
rsync_base=(rsync -az)
if [[ -n "${SSH_OPTS}" ]]; then
  rsync_base+=(-e "ssh ${SSH_OPTS}")
fi
"${rsync_base[@]}" "${LOCAL_BINARY}" "${HOST}:${REMOTE_WORKDIR}/hardener"
"${ssh_cmd[@]}" "${SUDO_CMD} chmod 0755 '${REMOTE_WORKDIR}/hardener'"

echo "Writing remote hardener config"
config_tmp="$(mktemp)"
cat >"${config_tmp}" <<EOF
version: "1"
profile: ${PROFILE}
state_dir: ${STATE_DIR}
output: ${OUTPUT}
lynis:
  report_path: ${REPORT_PATH}
EOF
"${rsync_base[@]}" "${config_tmp}" "${HOST}:${REMOTE_WORKDIR}/hardener.yaml"
rm -f "${config_tmp}"
if [[ "${SUDO_CMD}" != "" ]]; then
  "${ssh_cmd[@]}" "${SUDO_CMD} chmod 0644 '${REMOTE_WORKDIR}/hardener.yaml'"
fi

echo "Running Lynis audit on remote host"
"${ssh_cmd[@]}" "${SUDO_CMD} bash -lc \"${LYNIS_CMD}\""

echo "Running mandatory dry-run plan"
"${ssh_cmd[@]}" "${SUDO_CMD} '${REMOTE_WORKDIR}/hardener' apply --dry-run --config '${REMOTE_WORKDIR}/hardener.yaml' --state-dir '${STATE_DIR}' --profile '${PROFILE}' --output '${OUTPUT}'"

if [[ "${APPLY}" == "1" ]]; then
  echo "Running real apply"
  apply_cmd="${SUDO_CMD} '${REMOTE_WORKDIR}/hardener' apply --yes --config '${REMOTE_WORKDIR}/hardener.yaml' --state-dir '${STATE_DIR}' --profile '${PROFILE}' --output '${OUTPUT}'"
  if [[ "${CONFIRM_DANGEROUS}" == "1" ]]; then
    apply_cmd+=" --confirm-dangerous"
  fi
  "${ssh_cmd[@]}" "${apply_cmd}"

  latest_run_id="$("${ssh_cmd[@]}" "ls -1 '${STATE_DIR}/runs' 2>/dev/null | sort -n | tail -1 || true")"
  if [[ -n "${latest_run_id}" ]]; then
    echo "Latest run ID: ${latest_run_id}"
  fi
fi

if [[ -n "${ROLLBACK_RUN_ID}" ]]; then
  rb="${ROLLBACK_RUN_ID}"
  if [[ "${rb}" == "latest" ]]; then
    rb="$("${ssh_cmd[@]}" "ls -1 '${STATE_DIR}/runs' 2>/dev/null | sort -n | tail -1 || true")"
  fi
  if [[ -z "${rb}" ]]; then
    echo "Rollback requested but no run ID could be resolved." >&2
    exit 1
  fi
  echo "Running rollback for run ID: ${rb}"
  "${ssh_cmd[@]}" "${SUDO_CMD} '${REMOTE_WORKDIR}/hardener' rollback --run-id '${rb}' --yes --state-dir '${STATE_DIR}' --output '${OUTPUT}'"
fi

echo "Done."
