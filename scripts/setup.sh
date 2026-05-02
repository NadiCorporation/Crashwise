#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────────
# CrashWise — Universal Linux Setup Script
#
# Detects the host distribution and installs every system dependency required
# to build, fuzz, triage, and orchestrate. Supports:
#
#   • Arch family   (Arch, Manjaro, EndeavourOS)        — pacman + AUR fallback
#   • Debian family (Debian, Ubuntu, Kali, Mint)        — apt-get
#   • RedHat family (Fedora, RHEL, CentOS, Rocky, Alma) — dnf
#   • Void Linux                                        — xbps-install
#
# After system deps, bootstraps `uv`, creates the .venv, and runs `uv sync`.
#
# Usage:
#   ./scripts/setup.sh [flags]
#
# Flags:
#   --dry-run        Print the actions that would be taken; perform none.
#   --no-rust        Skip Rust toolchain installation.
#   --no-python      Skip uv/venv/Python deps step.
#   --skip-system    Skip system package installation (Python bootstrap only).
#   --no-aur         On Arch, do NOT use AUR fallback for missing packages.
#   --aur-helper=<x> Force AUR helper: yay | paru. Default: auto-detect, else yay.
#   -h, --help       Show this help.
#
# Copyright (c) 2026 CrashWise Contributors
# Licensed under the MIT License. See LICENSE in the project root.
# ──────────────────────────────────────────────────────────────────────────────

set -Eeuo pipefail
IFS=$'\n\t'

# ─── Globals ──────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
PROJECT_ROOT="$(cd -- "${SCRIPT_DIR}/.." &>/dev/null && pwd)"

DRY_RUN=0
SKIP_RUST=0
SKIP_PYTHON=0
SKIP_SYSTEM=0
USE_AUR=1
AUR_HELPER=""

DETECTED_FAMILY=""   # arch | debian | redhat | void
PKG_MANAGER=""       # pacman | apt-get | dnf | xbps-install
SUDO=""

# ─── Pretty logging ───────────────────────────────────────────────────────────
if [[ -t 1 ]]; then
  C_RESET=$'\033[0m'
  C_BOLD=$'\033[1m'
  C_DIM=$'\033[2m'
  C_RED=$'\033[31m'
  C_GREEN=$'\033[32m'
  C_YELLOW=$'\033[33m'
  C_BLUE=$'\033[34m'
  C_CYAN=$'\033[36m'
else
  C_RESET=""; C_BOLD=""; C_DIM=""
  C_RED=""; C_GREEN=""; C_YELLOW=""; C_BLUE=""; C_CYAN=""
fi

log()    { printf '%s[ %s•%s ] %s\n' "${C_DIM}"  "${C_RESET}" "${C_DIM}"  "$*${C_RESET}"; }
info()   { printf '%s[%sINFO%s ] %s\n' "${C_BOLD}" "${C_BLUE}"  "${C_RESET}" "$*"; }
ok()     { printf '%s[%s OK %s ] %s\n' "${C_BOLD}" "${C_GREEN}" "${C_RESET}" "$*"; }
warn()   { printf '%s[%sWARN%s ] %s\n' "${C_BOLD}" "${C_YELLOW}" "${C_RESET}" "$*" >&2; }
err()    { printf '%s[%sFAIL%s ] %s\n' "${C_BOLD}" "${C_RED}"   "${C_RESET}" "$*" >&2; }
banner() {
  printf '\n%s┌──────────────────────────────────────────────────────────────────┐%s\n' "${C_CYAN}" "${C_RESET}"
  printf '%s│ %-64s │%s\n' "${C_CYAN}" "$*" "${C_RESET}"
  printf '%s└──────────────────────────────────────────────────────────────────┘%s\n\n' "${C_CYAN}" "${C_RESET}"
}

die() { err "$*"; exit 1; }

on_err() {
  local exit_code=$?
  local line_no=$1
  err "Setup failed at line ${line_no} (exit ${exit_code})."
  err "Re-run with --dry-run for diagnostics, or open an issue with the log."
  exit "${exit_code}"
}
trap 'on_err ${LINENO}' ERR

# ─── Argument parsing ─────────────────────────────────────────────────────────
usage() {
  sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'
}

parse_args() {
  for arg in "$@"; do
    case "${arg}" in
      --dry-run)        DRY_RUN=1 ;;
      --no-rust)        SKIP_RUST=1 ;;
      --no-python)      SKIP_PYTHON=1 ;;
      --skip-system)    SKIP_SYSTEM=1 ;;
      --no-aur)         USE_AUR=0 ;;
      --aur-helper=*)   AUR_HELPER="${arg#*=}" ;;
      -h|--help)        usage; exit 0 ;;
      *)                die "Unknown flag: ${arg} (use --help)" ;;
    esac
  done
}

# ─── Run wrapper (dry-run aware) ──────────────────────────────────────────────
run() {
  if [[ ${DRY_RUN} -eq 1 ]]; then
    printf '%s$%s %s\n' "${C_DIM}" "${C_RESET}" "$*"
    return 0
  fi
  eval "$@"
}

run_as_user() {
  # Run as the invoking (non-root) user. Required for AUR helpers.
  local target_user="${SUDO_USER:-${USER}}"
  if [[ "${target_user}" == "root" ]]; then
    die "AUR operations require a non-root user. Re-run setup as your normal user (sudo will be invoked when needed)."
  fi
  if [[ ${DRY_RUN} -eq 1 ]]; then
    printf '%s$%s (as %s) %s\n' "${C_DIM}" "${C_RESET}" "${target_user}" "$*"
    return 0
  fi
  if [[ "$(id -un)" == "${target_user}" ]]; then
    eval "$@"
  else
    sudo -u "${target_user}" -H bash -lc "$*"
  fi
}

# ─── Sudo / privilege escalation ──────────────────────────────────────────────
ensure_sudo() {
  if [[ "$(id -u)" -eq 0 ]]; then
    SUDO=""
    return
  fi
  if ! command -v sudo &>/dev/null; then
    die "sudo not installed and not running as root."
  fi
  SUDO="sudo"
  info "Caching sudo credentials..."
  run "${SUDO} -v"
}

# ─── Distro detection ─────────────────────────────────────────────────────────
detect_distro() {
  banner "Detecting Linux distribution"

  local id="" id_like=""
  if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    id="${ID:-}"
    id_like="${ID_LIKE:-}"
  fi

  case "${id}" in
    arch|manjaro|endeavouros|garuda|artix)
      DETECTED_FAMILY="arch"; PKG_MANAGER="pacman" ;;
    debian|ubuntu|kali|linuxmint|pop|elementary|raspbian|neon)
      DETECTED_FAMILY="debian"; PKG_MANAGER="apt-get" ;;
    fedora|rhel|centos|rocky|almalinux|ol)
      DETECTED_FAMILY="redhat"; PKG_MANAGER="dnf" ;;
    void)
      DETECTED_FAMILY="void"; PKG_MANAGER="xbps-install" ;;
    *)
      # Fall back to ID_LIKE
      case "${id_like}" in
        *arch*)        DETECTED_FAMILY="arch";   PKG_MANAGER="pacman" ;;
        *debian*)      DETECTED_FAMILY="debian"; PKG_MANAGER="apt-get" ;;
        *rhel*|*fedora*) DETECTED_FAMILY="redhat"; PKG_MANAGER="dnf" ;;
        *)
          # Last resort: probe binaries
          if   command -v pacman        &>/dev/null; then DETECTED_FAMILY="arch";   PKG_MANAGER="pacman"
          elif command -v apt-get       &>/dev/null; then DETECTED_FAMILY="debian"; PKG_MANAGER="apt-get"
          elif command -v dnf           &>/dev/null; then DETECTED_FAMILY="redhat"; PKG_MANAGER="dnf"
          elif command -v xbps-install  &>/dev/null; then DETECTED_FAMILY="void";   PKG_MANAGER="xbps-install"
          else
            die "Unsupported distribution. Detected ID='${id}', ID_LIKE='${id_like}'."
          fi
          ;;
      esac
      ;;
  esac

  ok "Detected family: ${C_BOLD}${DETECTED_FAMILY}${C_RESET} (package manager: ${PKG_MANAGER})"
}

# ─── Package install helpers (per family) ─────────────────────────────────────
pacman_refresh() { run "${SUDO} pacman -Sy --noconfirm"; }
apt_refresh()    { run "${SUDO} apt-get update -y"; }
dnf_refresh()    { run "${SUDO} dnf -y makecache"; }
xbps_refresh()   { run "${SUDO} xbps-install -Syu xbps"; }

pacman_has() { pacman -Si "$1" &>/dev/null; }
pacman_installed() { pacman -Qi "$1" &>/dev/null; }

aur_helper_detect() {
  if [[ -n "${AUR_HELPER}" ]]; then
    if command -v "${AUR_HELPER}" &>/dev/null; then
      ok "Using AUR helper: ${AUR_HELPER}"
      return 0
    fi
    warn "Requested AUR helper '${AUR_HELPER}' not found; will bootstrap yay."
    AUR_HELPER=""
  fi
  for h in yay paru; do
    if command -v "$h" &>/dev/null; then
      AUR_HELPER="$h"
      ok "Detected AUR helper: ${AUR_HELPER}"
      return 0
    fi
  done
  return 1
}

aur_helper_bootstrap() {
  # Bootstrap `yay` from AUR using makepkg, as the invoking user.
  info "Bootstrapping 'yay' from AUR (requires base-devel + git)..."
  run "${SUDO} pacman -S --needed --noconfirm base-devel git"
  local tmp
  tmp="$(mktemp -d)"
  run_as_user "git clone https://aur.archlinux.org/yay.git '${tmp}/yay'"
  run_as_user "cd '${tmp}/yay' && makepkg -si --noconfirm"
  AUR_HELPER="yay"
  ok "AUR helper 'yay' installed."
}

aur_install() {
  # $1: package name
  if [[ ${USE_AUR} -eq 0 ]]; then
    warn "AUR fallback disabled (--no-aur). Skipping AUR package: $1"
    return 0
  fi
  if [[ -z "${AUR_HELPER}" ]] && ! aur_helper_detect; then
    aur_helper_bootstrap
  fi
  info "Installing from AUR: $1 (via ${AUR_HELPER})"
  run_as_user "${AUR_HELPER} -S --needed --noconfirm $1"
}

pacman_install_one() {
  # Install a single package; if missing in core repos and --no-aur not set,
  # try AUR as a fallback.
  local pkg="$1"
  if pacman_installed "${pkg}"; then
    log "pacman: ${pkg} already installed."
    return 0
  fi
  if pacman_has "${pkg}"; then
    run "${SUDO} pacman -S --needed --noconfirm ${pkg}"
  else
    warn "Package '${pkg}' not in official repos — trying AUR fallback."
    aur_install "${pkg}"
  fi
}

pacman_install() {
  local pkgs=("$@")
  for p in "${pkgs[@]}"; do
    pacman_install_one "${p}"
  done
}

apt_install() {
  run "${SUDO} DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends $*"
}
dnf_install() { run "${SUDO} dnf install -y $*"; }
xbps_install() { run "${SUDO} xbps-install -Sy $*"; }

# ─── System dependency lists ──────────────────────────────────────────────────
install_system_deps_arch() {
  banner "Installing system dependencies (Arch)"
  pacman_refresh
  # base-devel = group; pacman handles groups natively.
  pacman_install \
    base-devel git curl wget ca-certificates \
    clang llvm lld \
    cmake ninja pkgconf make \
    gdb valgrind binutils \
    python python-pip \
    docker docker-compose \
    jq unzip tar \
    afl++
}

install_system_deps_debian() {
  banner "Installing system dependencies (Debian/Ubuntu)"
  apt_refresh
  apt_install \
    build-essential git curl wget ca-certificates \
    clang llvm lld \
    cmake ninja-build pkg-config make \
    gdb valgrind binutils \
    python3 python3-pip python3-venv python3-dev \
    docker.io docker-compose-plugin \
    jq unzip tar
  # afl++ ships under different names depending on release
  if apt-cache show afl++ &>/dev/null; then
    apt_install afl++
  elif apt-cache show afl &>/dev/null; then
    apt_install afl
  else
    warn "afl++ not available in apt repos; install manually from https://github.com/AFLplusplus/AFLplusplus"
  fi
}

install_system_deps_redhat() {
  banner "Installing system dependencies (Fedora/RHEL)"
  dnf_refresh
  # Development Tools group
  run "${SUDO} dnf -y groupinstall 'Development Tools'"
  dnf_install \
    git curl wget ca-certificates \
    clang llvm lld \
    cmake ninja-build pkgconf-pkg-config make \
    gdb valgrind binutils \
    python3 python3-pip python3-devel \
    docker docker-compose \
    jq unzip tar
  if dnf list american-fuzzy-lop &>/dev/null; then
    dnf_install american-fuzzy-lop
  else
    warn "afl++ not in default dnf repos; install manually from https://github.com/AFLplusplus/AFLplusplus"
  fi
}

install_system_deps_void() {
  banner "Installing system dependencies (Void Linux)"
  xbps_refresh
  xbps_install \
    base-devel git curl wget \
    clang llvm lld \
    cmake ninja pkg-config make \
    gdb valgrind binutils \
    python3 python3-pip python3-devel \
    docker docker-compose \
    jq unzip tar
  if xbps-query -Rs afl++ &>/dev/null; then
    xbps_install afl++
  else
    warn "afl++ not available via xbps; install manually from https://github.com/AFLplusplus/AFLplusplus"
  fi
}

install_system_deps() {
  case "${DETECTED_FAMILY}" in
    arch)   install_system_deps_arch ;;
    debian) install_system_deps_debian ;;
    redhat) install_system_deps_redhat ;;
    void)   install_system_deps_void ;;
    *)      die "Unknown family: ${DETECTED_FAMILY}" ;;
  esac
  ok "System dependencies installed."
}

# ─── Rust toolchain ───────────────────────────────────────────────────────────
install_rust() {
  if [[ ${SKIP_RUST} -eq 1 ]]; then
    warn "Skipping Rust toolchain (--no-rust)."
    return 0
  fi
  banner "Installing Rust toolchain"
  if command -v rustc &>/dev/null && command -v cargo &>/dev/null; then
    ok "Rust already present: $(rustc --version)"
    return 0
  fi

  case "${DETECTED_FAMILY}" in
    arch)
      pacman_install rustup
      run_as_user "rustup default stable"
      ;;
    void)
      xbps_install rust cargo
      ;;
    debian|redhat)
      info "Bootstrapping rustup from https://sh.rustup.rs..."
      run_as_user "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable --profile minimal"
      ;;
  esac
  ok "Rust toolchain installed."
}

# ─── uv + Python project bootstrap ────────────────────────────────────────────
install_uv() {
  if command -v uv &>/dev/null; then
    ok "uv already installed: $(uv --version)"
    return 0
  fi
  info "Installing uv (https://astral.sh/uv)..."
  run_as_user "curl --proto '=https' --tlsv1.2 -LsSf https://astral.sh/uv/install.sh | sh"
  # uv installs to ~/.local/bin or ~/.cargo/bin depending on version.
  ok "uv installed."
}

bootstrap_python() {
  if [[ ${SKIP_PYTHON} -eq 1 ]]; then
    warn "Skipping Python bootstrap (--no-python)."
    return 0
  fi
  banner "Bootstrapping Python environment via uv"
  install_uv

  local uv_bin
  uv_bin="$(command -v uv || true)"
  if [[ -z "${uv_bin}" ]]; then
    # Common install paths
    for candidate in "${HOME}/.local/bin/uv" "${HOME}/.cargo/bin/uv"; do
      [[ -x "${candidate}" ]] && uv_bin="${candidate}" && break
    done
  fi
  [[ -z "${uv_bin}" ]] && die "uv not found on PATH after installation."

  info "Synchronising project dependencies (this creates .venv)..."
  run_as_user "cd '${PROJECT_ROOT}' && '${uv_bin}' sync"
  ok "Python environment ready at ${PROJECT_ROOT}/.venv"
}

# ─── Docker post-install niceties ─────────────────────────────────────────────
configure_docker() {
  if ! command -v docker &>/dev/null; then
    warn "Docker binary not found; skipping docker post-install."
    return 0
  fi
  info "Enabling docker service (best-effort)..."
  if command -v systemctl &>/dev/null; then
    run "${SUDO} systemctl enable --now docker || true"
  elif [[ -d /etc/sv ]]; then
    # Void / runit
    run "${SUDO} ln -sf /etc/sv/docker /var/service/ || true"
  fi

  local target_user="${SUDO_USER:-${USER}}"
  if [[ "${target_user}" != "root" ]] && ! id -nG "${target_user}" | grep -qw docker; then
    info "Adding ${target_user} to the 'docker' group..."
    run "${SUDO} usermod -aG docker '${target_user}' || true"
    warn "Log out & back in (or run 'newgrp docker') for group changes to take effect."
  fi
}

# ─── Final summary ────────────────────────────────────────────────────────────
print_summary() {
  banner "CrashWise setup complete"
  cat <<EOF
${C_BOLD}Next steps:${C_RESET}

  1. Activate the Python environment:
       ${C_CYAN}source ${PROJECT_ROOT}/.venv/bin/activate${C_RESET}

  2. Copy the env template & fill in your API keys:
       ${C_CYAN}cp ${PROJECT_ROOT}/.env.example ${PROJECT_ROOT}/.env${C_RESET}

  3. Spin up the local Temporal cluster:
       ${C_CYAN}docker compose -f ${PROJECT_ROOT}/docker-compose.yaml up -d${C_RESET}
       Web UI: http://localhost:8080

  4. Run the test suite:
       ${C_CYAN}uv run pytest${C_RESET}

Happy hunting. 🔧
EOF
}

# ─── Main ─────────────────────────────────────────────────────────────────────
main() {
  parse_args "$@"

  banner "CrashWise — Phase 0 setup"
  log  "Project root: ${PROJECT_ROOT}"
  log  "Dry run:       $([[ ${DRY_RUN}     -eq 1 ]] && echo yes || echo no)"
  log  "Skip system:   $([[ ${SKIP_SYSTEM} -eq 1 ]] && echo yes || echo no)"
  log  "Skip Python:   $([[ ${SKIP_PYTHON} -eq 1 ]] && echo yes || echo no)"
  log  "Skip Rust:     $([[ ${SKIP_RUST}   -eq 1 ]] && echo yes || echo no)"
  log  "AUR fallback:  $([[ ${USE_AUR}     -eq 1 ]] && echo yes || echo no)"

  detect_distro

  if [[ ${SKIP_SYSTEM} -eq 0 ]]; then
    ensure_sudo
    install_system_deps
    install_rust
    configure_docker
  else
    warn "Skipping all system-level installation (--skip-system)."
  fi

  bootstrap_python
  print_summary
}

main "$@"
