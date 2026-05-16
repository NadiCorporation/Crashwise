<!--
  SPDX-License-Identifier: MIT
  Copyright (c) 2026 CrashWise Contributors
-->

# Installation

## Prerequisites

| Requirement | Minimum |
|---|---|
| OS | Linux x86_64, kernel ≥ 5.10 |
| Python | 3.11, 3.12, or 3.13 |
| RAM | 8 GB |
| Disk | 50 GB free |
| Git | Any recent version |

All other dependencies (Docker, Clang, GCC, LLVM, AFL++) are provisioned by `crashwise setup`.

---

## Install CrashWise

```bash
git clone https://github.com/yahyatoubali/Crashwise.git && cd Crashwise
python -m venv .venv && source .venv/bin/activate
pip install -e .
crashwise version
```

---

## Provision System Dependencies

```bash
crashwise setup
```

This command:
1. Detects the Linux distribution from `/etc/os-release`
2. Installs Docker, Docker Compose v2, CMake, Clang, LLD, GCC, LLVM via the native package manager
3. Installs AFL++ (from AUR on Arch, from `universe` on Ubuntu)
4. Adds the current user to the `docker` group if missing
5. Starts the Docker daemon if stopped

### Non-interactive mode

```bash
crashwise setup --yes              # skip all prompts
crashwise setup --dry-run          # print commands without executing
crashwise setup --output setup.sh  # write script to file for review
```

### Verify

```bash
crashwise doctor
```

---

## Distro-Specific Notes

### Arch Linux

```bash
sudo pacman -S --needed python python-pip git base-devel
```

AFL++ is in the AUR:

```bash
yay -S aflplusplus
```

> Optional — the Docker worker image ships AFL++ pre-installed.

### Ubuntu (22.04 / 24.04)

```bash
sudo apt-get update
sudo apt-get install -y python3 python3-pip python3-venv git build-essential
```

> The AFL++ binary package is named `afl++` (not `aflplusplus`). If `apt` reports "Unable to locate package", run `sudo add-apt-repository universe && sudo apt-get update`.

### Fedora / RHEL

```bash
sudo dnf install python3 python3-pip git gcc gcc-c++ cmake clang llvm
```

---

## Infrastructure Stack

```bash
docker compose up -d
```

This starts:

| Service | Port | Purpose |
|---|---|---|
| Temporal Server | 7233 | Workflow orchestration (gRPC) |
| Temporal UI | 8233 | Web interface |
| PostgreSQL | 5432 | Persistence |
| Redis | 6379 | Distributed state |

### Initialize database

```bash
crashwise init
```

---

## First Campaign

```bash
crashwise run https://github.com/madler/zlib --timeout 600
```

The pre-flight gate validates Docker, Clang, and GCC before submission. Override with `--skip-preflight` if running inside the worker container.

### God-Mode signals (live campaign control)

```bash
crashwise signal <workflow_id> force_pivot
crashwise signal <workflow_id> inject_seed --data filename=poc.bin
crashwise signal <workflow_id> pause_hunt
```

Workflow IDs are printed by `crashwise run` and visible in Temporal UI at `http://localhost:8233`.

---

## Troubleshooting

### `docker-compose` v1 — `KeyError: 'ContainerConfig'`

The legacy Python `docker-compose` (v1.29.x) is incompatible with Docker Engine 24+. Switch to the v2 plugin:

```bash
# Arch
sudo pacman -Syu docker docker-compose docker-buildx

# Ubuntu
sudo apt-get remove docker-compose
sudo apt-get install docker-compose-plugin
```

Verify: `docker compose version` must report `v2.x.x`.

> Always use `docker compose` (space, no hyphen) — not `docker-compose`.

### "Permission denied" connecting to Docker daemon

Three distinct causes:

| Symptom | Fix |
|---|---|
| User just added to `docker` group | Log out and back in, or run `newgrp docker` |
| User not in `docker` group | `sudo usermod -aG docker $USER` then re-login |
| Docker daemon not running | `sudo systemctl start docker && sudo systemctl enable docker` |

`crashwise doctor` diagnoses which case applies.

### "Cannot reach Temporal at localhost:7233"

```bash
docker compose ps          # check if temporal is running
docker compose up -d       # bring it up
```

### `crashwise: command not found` under sudo

The binary lives in `.venv/bin/`. Either use the full path or avoid sudo:

```bash
./.venv/bin/crashwise doctor
# or
crashwise doctor   # no sudo needed for diagnostics
```

### "afl++ not found on host"

This is a warning, not a failure. The Docker worker ships AFL++ pre-installed. For host-native install:

- **Arch:** `yay -S aflplusplus`
- **Ubuntu:** `sudo apt-get install afl++`

---

## Uninstall

```bash
deactivate
rm -rf .venv

# System packages (optional):
sudo pacman -Rns docker docker-compose     # Arch
sudo apt-get purge docker.io docker-compose-plugin  # Ubuntu
```
