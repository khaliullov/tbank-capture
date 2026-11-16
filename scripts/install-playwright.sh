#!/usr/bin/env bash
# scripts/install-playwright.sh
# Reliable, reproducible Playwright driver & Chromium installation for tbank-capture.
set -euo pipefail

# 1. Detect project root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${PROJECT_ROOT}"

# Color output helpers (if terminal supports it)
if [ -t 1 ]; then
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    RED='\033[0;31m'
    BLUE='\033[0;34m'
    NC='\033[0m'
else
    GREEN=''
    YELLOW=''
    RED=''
    BLUE=''
    NC=''
fi

log_info() {
    printf "${BLUE}[INFO]${NC} %s\n" "$*"
}

log_ok() {
    printf "${GREEN}[OK]${NC} %s\n" "$*"
}

log_warn() {
    printf "${YELLOW}[WARN]${NC} %s\n" "$*"
}

log_err() {
    printf "${RED}[ERROR]${NC} %s\n" "$*" >&2
}

# Parse options
CHECK_ONLY=false
WITH_DEPS=false
FORCE=false

for arg in "$@"; do
    case "$arg" in
        --check)
            CHECK_ONLY=true
            ;;
        --with-deps)
            WITH_DEPS=true
            ;;
        --force)
            FORCE=true
            ;;
        --help|-h)
            cat <<EOF
Usage: $0 [OPTIONS]

Install Playwright driver and Chromium browser for tbank-capture.

Options:
  --check      Verify existing installation without downloading or modifying files
  --with-deps  On Linux, also install system dependencies required by Chromium
  --force      Force re-download of driver and browser even if present
  --help, -h   Show this help message
EOF
            exit 0
            ;;
        *)
            log_err "Unknown option: $arg"
            exit 1
            ;;
    esac
done

# 2. Verify Go is installed
if ! command -v go >/dev/null 2>&1; then
    log_err "Go is not installed or not in PATH."
    log_err "Please install Go 1.21+ from https://go.dev/dl/"
    exit 1
fi

GO_VERSION="$(go version)"
log_info "Detected Go: ${GO_VERSION}"

# 3. Determine driver version from pinned Go dependency
log_info "Inspecting Playwright Go dependency..."
PW_MOD_DIR="$(go list -m -f '{{.Dir}}' github.com/playwright-community/playwright-go 2>/dev/null || true)"
if [ -z "$PW_MOD_DIR" ] || [ ! -d "$PW_MOD_DIR" ]; then
    log_info "Downloading Go module dependencies..."
    go mod download
    PW_MOD_DIR="$(go list -m -f '{{.Dir}}' github.com/playwright-community/playwright-go)"
fi

if [ ! -f "${PW_MOD_DIR}/run.go" ]; then
    log_err "Could not find run.go in ${PW_MOD_DIR}"
    exit 1
fi

DRIVER_VERSION="$(grep -E 'playwrightCliVersion\s*=\s*' "${PW_MOD_DIR}/run.go" | sed -E 's/.*"([^"]+)".*/\1/' | tr -d '[:space:]')"
if [ -z "$DRIVER_VERSION" ]; then
    log_err "Failed to extract driver version from ${PW_MOD_DIR}/run.go"
    exit 1
fi

log_info "Required Playwright driver version: v${DRIVER_VERSION}"

# 4. Determine OS-specific cache directory
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"

if [ -n "${PLAYWRIGHT_DRIVER_PATH:-}" ]; then
    DRIVER_DIR="${PLAYWRIGHT_DRIVER_PATH}"
else
    case "${OS}" in
        darwin)
            CACHE_BASE="${HOME}/Library/Caches"
            ;;
        linux)
            CACHE_BASE="${XDG_CACHE_HOME:-$HOME/.cache}"
            ;;
        msys*|mingw*|cygwin*)
            CACHE_BASE="${LOCALAPPDATA:-$USERPROFILE/AppData/Local}"
            ;;
        *)
            CACHE_BASE="${HOME}/.cache"
            ;;
    esac
    DRIVER_DIR="${CACHE_BASE}/ms-playwright-go/${DRIVER_VERSION}"
fi

if [ -n "${PLAYWRIGHT_BROWSERS_PATH:-}" ]; then
    BROWSER_DIR="${PLAYWRIGHT_BROWSERS_PATH}"
else
    BROWSER_DIR="${CACHE_BASE}/ms-playwright"
fi

log_info "Target driver directory: ${DRIVER_DIR}"
log_info "Target browser directory: ${BROWSER_DIR}"

# Helper to check if driver is currently functional
check_driver_ready() {
    local cli_js="${DRIVER_DIR}/package/cli.js"
    if [ ! -f "${cli_js}" ]; then
        return 1
    fi

    local node_exec=""
    if [ -n "${PLAYWRIGHT_NODEJS_PATH:-}" ] && [ -x "${PLAYWRIGHT_NODEJS_PATH}" ]; then
        node_exec="${PLAYWRIGHT_NODEJS_PATH}"
    elif [ -x "${DRIVER_DIR}/node" ]; then
        node_exec="${DRIVER_DIR}/node"
    elif [ -x "${DRIVER_DIR}/node.exe" ]; then
        node_exec="${DRIVER_DIR}/node.exe"
    elif command -v node >/dev/null 2>&1; then
        node_exec="$(command -v node)"
    else
        return 1
    fi

    local version_out
    version_out="$("${node_exec}" "${cli_js}" --version 2>/dev/null || true)"
    if echo "${version_out}" | grep -q "${DRIVER_VERSION}"; then
        return 0
    fi
    return 1
}

# Helper to check if Chromium is installed
check_chromium_ready() {
    # Check for chromium-* directory with executable
    if [ ! -d "${BROWSER_DIR}" ]; then
        return 1
    fi

    # Try common chromium paths
    for p in \
        "${BROWSER_DIR}"/chromium-*/chrome-mac/Chromium.app/Contents/MacOS/Chromium \
        "${BROWSER_DIR}"/chromium-*/chrome-linux/chrome \
        "${BROWSER_DIR}"/chromium-*/chrome-win/chrome.exe \
        "${BROWSER_DIR}"/chromium-*/chrome \
        "${BROWSER_DIR}"/chromium-*/Chromium; do
        if [ -x "$p" ]; then
            return 0
        fi
    done
    return 1
}

# Check mode
if [ "${CHECK_ONLY}" = true ]; then
    log_info "Running Playwright preflight check..."
    DRIVER_OK=false
    BROWSER_OK=false

    if check_driver_ready; then
        DRIVER_OK=true
        log_ok "Driver: OK (v${DRIVER_VERSION} at ${DRIVER_DIR})"
    else
        log_err "Driver: MISSING or INCOMPATIBLE (expected v${DRIVER_VERSION} at ${DRIVER_DIR})"
    fi

    if check_chromium_ready; then
        BROWSER_OK=true
        log_ok "Chromium: OK (installed in ${BROWSER_DIR})"
    else
        log_err "Chromium: MISSING in ${BROWSER_DIR}"
    fi

    if [ "${DRIVER_OK}" = true ] && [ "${BROWSER_OK}" = true ]; then
        log_ok "Playwright check passed: driver and Chromium are ready."
        exit 0
    else
        log_err "Playwright check failed. Run 'make playwright-install' to install missing components."
        exit 1
    fi
fi

# 5. Install Playwright driver if missing or forced
if [ "${FORCE}" = true ] || ! check_driver_ready; then
    log_info "Installing Playwright driver v${DRIVER_VERSION}..."
    mkdir -p "${DRIVER_DIR}"

    # Download official playwright-core npm package for exact driver CLI
    NPM_URL="https://registry.npmjs.org/playwright-core/-/playwright-core-${DRIVER_VERSION}.tgz"
    TMP_DIR="$(mktemp -d)"
    trap 'rm -rf "${TMP_DIR}"' EXIT

    log_info "Downloading driver bundle from ${NPM_URL}..."
    if ! curl -fsSL "${NPM_URL}" -o "${TMP_DIR}/core.tgz"; then
        log_err "Failed to download playwright-core from ${NPM_URL}"
        exit 1
    fi

    log_info "Extracting driver bundle..."
    tar -xzf "${TMP_DIR}/core.tgz" -C "${TMP_DIR}"
    rm -rf "${DRIVER_DIR}/package"
    mv "${TMP_DIR}/package" "${DRIVER_DIR}/package"

    # Ensure Node.js binary is available for the driver
    if [ ! -x "${DRIVER_DIR}/node" ] && [ ! -x "${DRIVER_DIR}/node.exe" ]; then
        if command -v node >/dev/null 2>&1; then
            SYS_NODE="$(command -v node)"
            log_info "Configuring driver to use host Node.js (${SYS_NODE})..."
            cp "${SYS_NODE}" "${DRIVER_DIR}/node" || ln -sf "${SYS_NODE}" "${DRIVER_DIR}/node" || true
            chmod +x "${DRIVER_DIR}/node" 2>/dev/null || true
        else
            log_info "Host Node.js not found; downloading standalone Node.js runtime..."
            NODE_VERSION="v20.18.0"
            case "${OS}" in
                darwin)
                    NODE_OS="darwin"
                    ;;
                linux)
                    NODE_OS="linux"
                    ;;
                *)
                    NODE_OS="linux"
                    ;;
            esac
            case "${ARCH}" in
                x86_64|amd64)
                    NODE_ARCH="x64"
                    ;;
                arm64|aarch64)
                    NODE_ARCH="arm64"
                    ;;
                *)
                    NODE_ARCH="x64"
                    ;;
            esac

            NODE_URL="https://nodejs.org/dist/${NODE_VERSION}/node-${NODE_VERSION}-${NODE_OS}-${NODE_ARCH}.tar.gz"
            log_info "Fetching Node.js from ${NODE_URL}..."
            if curl -fsSL "${NODE_URL}" -o "${TMP_DIR}/node.tar.gz"; then
                tar -xzf "${TMP_DIR}/node.tar.gz" -C "${TMP_DIR}"
                cp "${TMP_DIR}/node-${NODE_VERSION}-${NODE_OS}-${NODE_ARCH}/bin/node" "${DRIVER_DIR}/node"
                chmod +x "${DRIVER_DIR}/node"
            else
                log_warn "Could not download standalone Node.js; will attempt system execution."
            fi
        fi
    fi

    if ! check_driver_ready; then
        log_err "Driver installation finished but verification failed."
        exit 1
    fi
    log_ok "Driver v${DRIVER_VERSION} installed successfully."
else
    log_ok "Playwright driver v${DRIVER_VERSION} is already installed."
fi

# 6. Install Chromium browser binary using the pinned Go library
log_info "Installing Chromium browser using pinned Playwright Go dependency..."
INSTALL_ARGS=("install" "chromium")

if [ "${WITH_DEPS}" = true ]; then
    log_info "Option --with-deps enabled: installing system dependencies (Linux)..."
    INSTALL_ARGS=("install" "--with-deps" "chromium")
fi

if ! go run github.com/playwright-community/playwright-go/cmd/playwright "${INSTALL_ARGS[@]}"; then
    log_err "Chromium installation failed."
    exit 1
fi

# 7. Final Verification
if ! check_chromium_ready; then
    log_err "Chromium installation succeeded but executable was not found."
    exit 1
fi

log_ok "Chromium browser installed successfully."
log_ok "Playwright setup complete! You can now build and run tbank-capture."
