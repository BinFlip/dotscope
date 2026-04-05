#!/usr/bin/env bash
#
# Regenerate all obfuscator test samples via a Windows SSH host.
#
# This script copies the shared TestApp source, configs, and generation scripts
# to a Windows machine, runs each obfuscator's generate.ps1 remotely, then
# copies the resulting .exe files back into the local test sample directories.
#
# Environment variables (required):
#   WINDOWS_HOST  - SSH host string, e.g. "user@host" or "user@host -p 2222"
#   REMOTE_DIR    - Working directory on the Windows host, e.g. "C:/Users/you/dotscope_samples"
#
# Usage:
#   export WINDOWS_HOST="user@host -p 22"
#   export REMOTE_DIR="C:/Users/you/dotscope_samples"
#   ./regenerate.sh                        # Regenerate all obfuscators
#   ./regenerate.sh confuserex             # Regenerate ConfuserEx only
#   ./regenerate.sh bitmono obfuscar       # Regenerate BitMono and Obfuscar
#   ./regenerate.sh jiejie                 # Regenerate JIEJIE.NET only
#
# Prerequisites:
#   - SSH key-based auth configured for the Windows host
#   - Windows host has: .NET SDK 8.0+, .NET Framework 4.8 SDK, Git

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log()  { echo -e "${CYAN}[regenerate]${NC} $*"; }
ok()   { echo -e "${GREEN}[regenerate]${NC} $*"; }
warn() { echo -e "${YELLOW}[regenerate]${NC} $*"; }
err()  { echo -e "${RED}[regenerate]${NC} $*" >&2; }

# SSH connection (required env vars)
if [ -z "${WINDOWS_HOST:-}" ]; then
    err "WINDOWS_HOST is not set. Export it first, e.g.:"
    err "  export WINDOWS_HOST='user@host -p 22'"
    exit 1
fi
if [ -z "${REMOTE_DIR:-}" ]; then
    err "REMOTE_DIR is not set. Export it first, e.g.:"
    err "  export REMOTE_DIR='C:/Users/you/dotscope_samples'"
    exit 1
fi

# Local paths — scripts live at the obfuscator level, configs/samples in version subdirs
TESTAPP_DIR="$SCRIPT_DIR/source/TestApp"
CONFUSEREX_SCRIPT="$SCRIPT_DIR/confuserex/generate.ps1"
CONFUSEREX_SAMPLES="$SCRIPT_DIR/confuserex/1.6.0"
BITMONO_SCRIPT="$SCRIPT_DIR/bitmono/generate.ps1"
BITMONO_SAMPLES="$SCRIPT_DIR/bitmono/0.39.0"
OBFUSCAR_SCRIPT="$SCRIPT_DIR/obfuscar/generate.ps1"
OBFUSCAR_SAMPLES="$SCRIPT_DIR/obfuscar/2.2.50"
JIEJIE_SCRIPT="$SCRIPT_DIR/jiejie/source/generate.ps1"
JIEJIE_SAMPLES="$SCRIPT_DIR/jiejie/source"

# Build SSH command array — handles port and user@host
build_ssh_args() {
    read -ra SSH_PARTS <<< "$WINDOWS_HOST"
    SSH_ARGS=("${SSH_PARTS[@]}")
}

# Run a command on the remote host via PowerShell (Windows SSH defaults to CMD)
run_ssh() {
    ssh "${SSH_ARGS[@]}" "powershell -NoProfile -Command \"$*\""
}

# Run a raw command (no PowerShell wrapper) for simple cases
run_ssh_raw() {
    ssh "${SSH_ARGS[@]}" "$@"
}

# Extract host and port from SSH_ARGS once for scp usage
parse_scp_args() {
    SCP_HOST=""
    SCP_PORT_ARGS=()
    local i=0
    while [ $i -lt ${#SSH_ARGS[@]} ]; do
        case "${SSH_ARGS[$i]}" in
            -p)
                SCP_PORT_ARGS=(-P "${SSH_ARGS[$((i+1))]}")
                i=$((i+2))
                ;;
            *)
                SCP_HOST="${SSH_ARGS[$i]}"
                i=$((i+1))
                ;;
        esac
    done
}

run_scp_to() {
    local src="$1" dst="$2"
    scp "${SCP_PORT_ARGS[@]}" -r "$src" "${SCP_HOST}:${dst}"
}

# Download all .exe files from a remote directory
download_exes() {
    local remote_dir="$1" local_dir="$2"
    # List remote .exe files, then download each one
    local files
    files=$(run_ssh "Get-ChildItem -Path '${remote_dir}' -Filter '*.exe' | ForEach-Object { \$_.Name }" 2>/dev/null | tr -d '\r')
    if [ -z "$files" ]; then
        warn "No .exe files found in remote directory $remote_dir"
        return 1
    fi
    while IFS= read -r f; do
        [ -z "$f" ] && continue
        scp "${SCP_PORT_ARGS[@]}" "${SCP_HOST}:${remote_dir}/${f}" "${local_dir}/"
    done <<< "$files"
}

# Determine which obfuscators to regenerate
TARGETS=("$@")
if [ ${#TARGETS[@]} -eq 0 ]; then
    TARGETS=(confuserex bitmono obfuscar jiejie)
fi

build_ssh_args
parse_scp_args

# ── Step 1: Verify SSH connectivity ──────────────────────────────────────────
log "Testing SSH connection to $WINDOWS_HOST..."
if ! run_ssh_raw "echo ok" >/dev/null 2>&1; then
    err "Cannot connect to Windows host. Check WINDOWS_HOST env var and SSH keys."
    exit 1
fi
ok "SSH connection verified."

# ── Step 2: Prepare remote working directory ─────────────────────────────────
log "Creating remote directory $REMOTE_DIR..."
run_ssh "New-Item -ItemType Directory -Path '${REMOTE_DIR}/TestApp/Resources' -Force | Out-Null; \
         New-Item -ItemType Directory -Path '${REMOTE_DIR}/output' -Force | Out-Null"

# ── Step 3: Upload TestApp source ────────────────────────────────────────────
log "Uploading TestApp source..."
run_scp_to "$TESTAPP_DIR/Program.cs" "$REMOTE_DIR/TestApp/"
run_scp_to "$TESTAPP_DIR/TestApp.csproj" "$REMOTE_DIR/TestApp/"
run_scp_to "$TESTAPP_DIR/Resources/greeting.txt" "$REMOTE_DIR/TestApp/Resources/"
run_scp_to "$TESTAPP_DIR/Resources/data.bin" "$REMOTE_DIR/TestApp/Resources/"
ok "TestApp source uploaded."

# ── Step 4: Run each obfuscator ──────────────────────────────────────────────

regenerate_confuserex() {
    log "=== ConfuserEx ==="

    # Upload generation script and configs
    run_ssh "New-Item -ItemType Directory -Path '${REMOTE_DIR}/confuserex/configs' -Force | Out-Null"
    run_scp_to "$CONFUSEREX_SCRIPT" "$REMOTE_DIR/confuserex/"
    for f in "$CONFUSEREX_SAMPLES"/*.crproj; do
        run_scp_to "$f" "$REMOTE_DIR/confuserex/configs/"
    done

    # Run generation
    log "Running ConfuserEx generate.ps1..."
    run_ssh "& '${REMOTE_DIR}/confuserex/generate.ps1' \
        -TestAppPath '${REMOTE_DIR}/TestApp/TestApp.csproj' \
        -OutputDir '${REMOTE_DIR}/output/confuserex' \
        -ConfigDir '${REMOTE_DIR}/confuserex/configs'"

    # Download results
    log "Downloading ConfuserEx samples..."
    download_exes "$REMOTE_DIR/output/confuserex" "$CONFUSEREX_SAMPLES"

    local count
    count=$(ls "$CONFUSEREX_SAMPLES"/*.exe 2>/dev/null | wc -l | tr -d ' ')
    ok "ConfuserEx: $count samples in place."
}

regenerate_bitmono() {
    log "=== BitMono ==="

    # Upload generation script and configs
    run_ssh "New-Item -ItemType Directory -Path '${REMOTE_DIR}/bitmono/configs' -Force | Out-Null"
    run_scp_to "$BITMONO_SCRIPT" "$REMOTE_DIR/bitmono/"
    for f in "$BITMONO_SAMPLES"/*.json; do
        run_scp_to "$f" "$REMOTE_DIR/bitmono/configs/"
    done

    # Run generation
    log "Running BitMono generate.ps1..."
    run_ssh "& '${REMOTE_DIR}/bitmono/generate.ps1' \
        -TestAppPath '${REMOTE_DIR}/TestApp/TestApp.csproj' \
        -OutputDir '${REMOTE_DIR}/output/bitmono' \
        -ConfigDir '${REMOTE_DIR}/bitmono/configs'"

    # Download results
    log "Downloading BitMono samples..."
    download_exes "$REMOTE_DIR/output/bitmono" "$BITMONO_SAMPLES"

    local count
    count=$(ls "$BITMONO_SAMPLES"/*.exe 2>/dev/null | wc -l | tr -d ' ')
    ok "BitMono: $count samples in place."
}

regenerate_obfuscar() {
    log "=== Obfuscar ==="

    # Upload generation script and configs
    run_ssh "New-Item -ItemType Directory -Path '${REMOTE_DIR}/obfuscar/configs' -Force | Out-Null"
    run_scp_to "$OBFUSCAR_SCRIPT" "$REMOTE_DIR/obfuscar/"
    for f in "$OBFUSCAR_SAMPLES"/*.xml; do
        run_scp_to "$f" "$REMOTE_DIR/obfuscar/configs/"
    done

    # Run generation
    log "Running Obfuscar generate.ps1..."
    run_ssh "& '${REMOTE_DIR}/obfuscar/generate.ps1' \
        -TestAppPath '${REMOTE_DIR}/TestApp/TestApp.csproj' \
        -OutputDir '${REMOTE_DIR}/output/obfuscar' \
        -ConfigDir '${REMOTE_DIR}/obfuscar/configs'"

    # Download results
    log "Downloading Obfuscar samples..."
    download_exes "$REMOTE_DIR/output/obfuscar" "$OBFUSCAR_SAMPLES"

    local count
    count=$(ls "$OBFUSCAR_SAMPLES"/*.exe 2>/dev/null | wc -l | tr -d ' ')
    ok "Obfuscar: $count samples in place."
}

regenerate_jiejie() {
    log "=== JIEJIE.NET ==="

    # Upload generation script (JIEJIE has no separate config files)
    run_ssh "New-Item -ItemType Directory -Path '${REMOTE_DIR}/jiejie' -Force | Out-Null"
    run_scp_to "$JIEJIE_SCRIPT" "$REMOTE_DIR/jiejie/"

    # Run generation
    log "Running JIEJIE.NET generate.ps1..."
    run_ssh "& '${REMOTE_DIR}/jiejie/generate.ps1' \
        -TestAppPath '${REMOTE_DIR}/TestApp/TestApp.csproj' \
        -OutputDir '${REMOTE_DIR}/output/jiejie'"

    # Download results
    log "Downloading JIEJIE.NET samples..."
    download_exes "$REMOTE_DIR/output/jiejie" "$JIEJIE_SAMPLES"

    local count
    count=$(ls "$JIEJIE_SAMPLES"/*.exe 2>/dev/null | wc -l | tr -d ' ')
    ok "JIEJIE.NET: $count samples in place."
}

for target in "${TARGETS[@]}"; do
    case "$target" in
        confuserex) regenerate_confuserex ;;
        bitmono)    regenerate_bitmono ;;
        obfuscar)   regenerate_obfuscar ;;
        jiejie)     regenerate_jiejie ;;
        *)
            err "Unknown target: $target (valid: confuserex, bitmono, obfuscar, jiejie)"
            exit 1
            ;;
    esac
done

# ── Step 5: Summary ──────────────────────────────────────────────────────────
echo ""
log "════════════════════════════════════════════════════════════════"
ok "Regeneration complete for: ${TARGETS[*]}"
log ""
log "Verify with:"
for target in "${TARGETS[@]}"; do
    log "  cargo test --release --test $target"
done
log ""
log "Or all at once:"
log "  cargo test --release --test confuserex --test bitmono --test obfuscar --test jiejie"
log "════════════════════════════════════════════════════════════════"
