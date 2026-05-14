#!/usr/bin/env bash
set -euo pipefail

# hardener one-line installer
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/<owner>/<repo>/main/scripts/install.sh | bash
#
# Optional environment variables:
#   HARDENER_INSTALL_REPO=maestroi/lynis-autofix
#   HARDENER_INSTALL_VERSION=latest            # e.g. v0.1.0
#   HARDENER_INSTALL_METHOD=auto               # auto|release|source
#   HARDENER_INSTALL_DIR=/usr/local/bin

REPO="${HARDENER_INSTALL_REPO:-maestroi/lynis-autofix}"
VERSION="${HARDENER_INSTALL_VERSION:-latest}"
METHOD="${HARDENER_INSTALL_METHOD:-auto}"
INSTALL_DIR="${HARDENER_INSTALL_DIR:-/usr/local/bin}"
BIN_NAME="hardener"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

log() { printf '[install] %s\n' "$*"; }
warn() { printf '[install] WARN: %s\n' "$*" >&2; }
err() { printf '[install] ERROR: %s\n' "$*" >&2; }

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    err "missing required command: $1"
    exit 1
  }
}

detect_os() {
  local os
  os="$(uname -s | tr '[:upper:]' '[:lower:]')"
  case "$os" in
    linux|darwin) printf '%s' "$os" ;;
    *)
      err "unsupported OS: $os (supported: linux, darwin)"
      exit 1
      ;;
  esac
}

detect_arch() {
  local arch
  arch="$(uname -m)"
  case "$arch" in
    x86_64|amd64) printf 'amd64' ;;
    aarch64|arm64) printf 'arm64' ;;
    *)
      err "unsupported architecture: $arch (supported: amd64, arm64)"
      exit 1
      ;;
  esac
}

normalize_tag() {
  local v="$1"
  if [[ "$v" == "latest" ]]; then
    printf 'latest'
    return
  fi
  if [[ "$v" == v* ]]; then
    printf '%s' "$v"
  else
    printf 'v%s' "$v"
  fi
}

fetch_release_json() {
  local tag="$1"
  if [[ "$tag" == "latest" ]]; then
    curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest"
  else
    curl -fsSL "https://api.github.com/repos/${REPO}/releases/tags/${tag}"
  fi
}

json_tag_name() {
  sed -n 's/.*"tag_name":[[:space:]]*"\([^"]*\)".*/\1/p' | head -n1
}

pick_release_asset_url() {
  local os="$1"
  local arch="$2"
  local tag="$3"

  # Prefer assets that include os+arch and are tar.gz or raw binary.
  sed -n 's/.*"browser_download_url":[[:space:]]*"\([^"]*\)".*/\1/p' \
    | grep -E "/(hardener|${BIN_NAME}).*(${tag#v}|${tag})?.*(${os}|linux|darwin).*(amd64|arm64).*(\\.tar\\.gz|$)" \
    | grep -E "${os}.*${arch}|${arch}.*${os}" \
    | head -n1
}

install_file() {
  local src="$1"
  local dest="${INSTALL_DIR}/${BIN_NAME}"

  if [[ -w "${INSTALL_DIR}" ]] || [[ ! -e "${INSTALL_DIR}" && -w "$(dirname "${INSTALL_DIR}")" ]]; then
    mkdir -p "${INSTALL_DIR}"
    install -m 0755 "${src}" "${dest}"
  else
    if command -v sudo >/dev/null 2>&1; then
      sudo mkdir -p "${INSTALL_DIR}"
      sudo install -m 0755 "${src}" "${dest}"
    else
      err "no write permission to ${INSTALL_DIR} and sudo is not available"
      exit 1
    fi
  fi

  log "installed ${BIN_NAME} to ${dest}"
}

install_from_release() {
  local os="$1"
  local arch="$2"
  local tag="$3"

  need_cmd curl
  need_cmd tar

  log "attempting GitHub release install (${REPO}, ${tag}, ${os}/${arch})"
  local release_json
  if ! release_json="$(fetch_release_json "$tag")"; then
    warn "failed to fetch release metadata"
    return 1
  fi

  local resolved_tag
  resolved_tag="$(printf '%s' "${release_json}" | json_tag_name)"
  if [[ -z "${resolved_tag}" ]]; then
    warn "release metadata does not contain tag_name"
    return 1
  fi

  local asset_url
  asset_url="$(printf '%s' "${release_json}" | pick_release_asset_url "${os}" "${arch}" "${resolved_tag}")"
  if [[ -z "${asset_url}" ]]; then
    warn "no matching release asset found for ${os}/${arch}"
    return 1
  fi

  local archive="${TMP_DIR}/hardener-release"
  curl -fsSL "${asset_url}" -o "${archive}"

  local bin_path="${TMP_DIR}/${BIN_NAME}"
  if [[ "${asset_url}" == *.tar.gz ]]; then
    tar -xzf "${archive}" -C "${TMP_DIR}"
    if [[ -f "${TMP_DIR}/${BIN_NAME}" ]]; then
      :
    else
      local found
      found="$(find "${TMP_DIR}" -maxdepth 3 -type f -name "${BIN_NAME}" | head -n1 || true)"
      if [[ -z "${found}" ]]; then
        warn "release asset downloaded but ${BIN_NAME} not found in archive"
        return 1
      fi
      cp "${found}" "${bin_path}"
    fi
  else
    cp "${archive}" "${bin_path}"
  fi

  chmod +x "${bin_path}"
  install_file "${bin_path}"
  return 0
}

install_from_source() {
  local tag="$1"
  need_cmd git
  need_cmd go

  log "installing from source (git clone + go build) from ${REPO} (${tag})"
  local src_dir="${TMP_DIR}/src"
  local repo_url="https://github.com/${REPO}.git"

  if [[ "${tag}" == "latest" ]]; then
    git clone --depth 1 "${repo_url}" "${src_dir}"
  else
    git clone --depth 1 --branch "${tag}" "${repo_url}" "${src_dir}"
  fi

  (
    cd "${src_dir}"
    if [[ ! -f "go.mod" ]]; then
      err "repository ${REPO} does not contain go.mod on the selected ref (${tag})"
      err "publish a release asset or push the Go CLI project to that branch/tag"
      exit 1
    fi
    go build -o "${TMP_DIR}/${BIN_NAME}" .
  )

  if [[ ! -f "${TMP_DIR}/${BIN_NAME}" ]]; then
    err "go build completed but ${BIN_NAME} binary not found"
    exit 1
  fi

  install_file "${TMP_DIR}/${BIN_NAME}"
}

main() {
  need_cmd install

  local os arch tag
  os="$(detect_os)"
  arch="$(detect_arch)"
  tag="$(normalize_tag "${VERSION}")"

  case "${METHOD}" in
    release)
      install_from_release "${os}" "${arch}" "${tag}" || {
        err "release install failed"
        exit 1
      }
      ;;
    source)
      install_from_source "${tag}"
      ;;
    auto)
      if ! install_from_release "${os}" "${arch}" "${tag}"; then
        warn "falling back to source build"
        install_from_source "${tag}"
      fi
      ;;
    *)
      err "invalid HARDENER_INSTALL_METHOD: ${METHOD} (expected auto|release|source)"
      exit 1
      ;;
  esac

  log "done"
  log "run: ${BIN_NAME} --help"
}

main "$@"
