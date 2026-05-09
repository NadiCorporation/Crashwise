# CrashWise — Zero-Friction Install Guide

This guide walks you through installing and running CrashWise on a fresh
**Arch Linux** or **Ubuntu** machine. It is designed for the
"`git clone` → `pip install -e .` → `crashwise run`" workflow with
zero manual dependency hunting.

> **TL;DR (any distro):**
> ```bash
> git clone https://github.com/yahyatoubali/Crashwise && cd Crashwise
> python -m venv .venv && source .venv/bin/activate
> pip install -e .
> crashwise setup     # interactive: installs deps, fixes docker group
> crashwise doctor    # verify
> crashwise run       # off you go
> ```

---

## 0. Prerequisites (any distro)

* Linux x86_64 (kernel ≥ 5.10).
* Python ≥ 3.11 (3.11 / 3.12 / 3.13 supported).
* `git`.
* At least 8 GB RAM and 50 GB free disk for fuzzing campaigns.

Everything else (Docker, Clang, GCC, LLVM, AFL++, …) is provisioned
automatically by `crashwise setup`.

---

## 1. Arch Linux 🐧

### 1.1 Install Python + Git

```bash
sudo pacman -S --needed python python-pip git base-devel
```

### 1.2 Clone & install CrashWise

```bash
git clone https://github.com/yahyatoubali/Crashwise
cd Crashwise

# Recommended: use uv (project standard) or a plain venv.
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

After the install completes, `crashwise` is on your `$PATH`:

```bash
crashwise version
# → crashwise 0.1.0
```

### 1.3 Provision system dependencies

```bash
crashwise setup
```

This single command will:

1. Detect Arch from `/etc/os-release`.
2. Install **`docker`, `docker-compose`, `cmake`, `clang`, `lld`,
   `gcc`, `llvm`** via `sudo pacman -S --needed`.
3. Detect that **`aflplusplus`** lives in the AUR and either:
   * Use your `yay` / `paru` if available, or
   * Print clear AUR-bootstrap instructions (and remind you that the
     Docker worker ships AFL++ pre-installed, so this is optional).
4. Notice if your user is **not** in the `docker` group and offer to
   run `sudo usermod -aG docker $USER` for you.
5. Notice if the Docker daemon is not running and offer to run
   `sudo systemctl start docker` for you.

If you prefer a non-interactive run (e.g. inside a provisioning script):

```bash
crashwise setup --yes              # no prompts
crashwise setup --dry-run          # print the script without executing
crashwise setup --output setup.sh  # write to a file you can review
```

### 1.4 Optional: install AFL++ from the AUR

```bash
# If you don't have an AUR helper yet:
sudo pacman -S --needed base-devel git
git clone https://aur.archlinux.org/yay.git && cd yay && makepkg -si

# Then:
yay -S aflplusplus
```

You can skip this entirely — the Dockerised worker includes AFL++.

### 1.5 Verify

```bash
# Log out / log back in if `crashwise setup` added you to the docker group
# (or run `newgrp docker` for the current shell).

crashwise doctor
# → All green. System is ready for CrashWise.
```

---

## 2. Ubuntu 🐧

Tested on **Ubuntu 22.04 LTS** and **Ubuntu 24.04 LTS**.

### 2.1 Install Python + Git

```bash
sudo apt-get update
sudo apt-get install -y python3 python3-pip python3-venv git build-essential
```

### 2.2 Clone & install CrashWise

```bash
git clone https://github.com/yahyatoubali/Crashwise
cd Crashwise

python3 -m venv .venv
source .venv/bin/activate
pip install -e .

crashwise version
# → crashwise 0.1.0
```

### 2.3 Provision system dependencies

```bash
crashwise setup
```

This will:

1. Detect Ubuntu from `/etc/os-release`.
2. Install **`docker.io`, `docker-compose-plugin`, `cmake`, `clang`,
   `lld`, `gcc`, `g++`, `llvm-dev`, `aflplusplus`** via
   `sudo apt-get install -y`.
3. Offer to add you to the `docker` group with `sudo usermod -aG docker
   $USER`.
4. Offer to start the Docker daemon with `sudo systemctl start docker`
   if it's down.

> ℹ️ On Ubuntu, AFL++ is in `universe`. If `apt` complains about
> `aflplusplus` being unavailable, run
> `sudo add-apt-repository universe && sudo apt-get update` and re-run
> `crashwise setup`.

### 2.4 Verify

```bash
# Log out / log back in (or `newgrp docker`) for the docker group change.
crashwise doctor
```

---

## 3. Moving the project between machines (Yahya's flow)

```bash
# On the source machine:
cd ~/Projects/Crashwise
git status            # commit / push anything pending
git push origin master

# On the destination machine (Arch or Ubuntu):
cd ~/Projects
git clone https://github.com/yahyatoubali/Crashwise
cd Crashwise
python -m venv .venv && source .venv/bin/activate
pip install -e .
crashwise setup       # picks the correct package manager automatically
crashwise doctor
```

That's the full migration. The Sentinel handles every distro-specific
divergence — there is no longer any "remember to apt-get this on
Ubuntu" or "yay -S that on Arch" mental tax.

---

## 4. Running your first campaign

```bash
# 1. Start the local Temporal cluster + Redis + workers via docker-compose:
docker compose up -d

# 2. Initialise the local SQLite DB:
crashwise init

# 3. Submit a campaign. The pre-flight gate will refuse to start if
#    Docker / Clang / GCC are missing, with an actionable hint.
crashwise run https://github.com/libjxl/libjxl \
    --fuzzer libfuzzer \
    --timeout 1800

# 4. Open the dashboard (separate terminal):
crashwise dashboard
# → http://localhost:8501
```

### Bypassing the pre-flight gate

The pre-flight gate is mandatory by default. If you're certain the host
is configured (e.g. inside the Dockerised worker), pass
`--skip-preflight`:

```bash
crashwise run https://github.com/libjxl/libjxl --skip-preflight
```

### God-Mode signals while a campaign is running

```bash
crashwise signal <workflow_id> force_pivot --data "JXL plateau"
crashwise signal <workflow_id> inject_seed --data filename=/tmp/poc.jxl
crashwise signal <workflow_id> pause_hunt
crashwise signal <workflow_id> resume_hunt
```

The workflow ID is printed by `crashwise run` and visible in the
Temporal Web UI at `http://localhost:8233`.

---

## 5. Troubleshooting

### "Cannot connect to the Docker daemon"

```bash
# Did you log out / back in after `crashwise setup` added you to the
# docker group?
groups | grep -q docker || newgrp docker

# Daemon down?
sudo systemctl start docker
sudo systemctl enable docker        # start on boot
```

### "afl++ not found on host"

This is a **warning**, not a failure. The Docker worker images ship
AFL++ pre-installed. If you want a host-native install:

* **Arch:** `yay -S aflplusplus` (AUR).
* **Ubuntu 22.04+:** `sudo apt-get install aflplusplus`.

### "Pre-flight failed — campaign refused"

`crashwise run` only refuses when one of the **critical** dependencies
is missing:

* `runtime.docker` — fuzz containers cannot launch.
* `build.clang` — harness compiler.
* `build.gcc` — fallback compiler.

Run `crashwise doctor` for the full report and `crashwise setup` to
auto-install the missing pieces.

### "Cannot reach Temporal at localhost:7233"

```bash
docker compose ps               # is `temporal` running?
docker compose up -d temporal   # bring it up if not
```

### Conda / system Python conflicts

Always use a venv:

```bash
deactivate                   # if a conda env is active
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

---

## 6. Uninstall

```bash
# CrashWise is installed in editable mode — just remove the venv.
deactivate
rm -rf .venv

# To uninstall system-wide packages installed by `crashwise setup`,
# use your distro's normal package manager:
sudo pacman -Rns docker docker-compose          # Arch
sudo apt-get purge docker.io docker-compose-plugin   # Ubuntu
```

---

## Appendix: What `crashwise setup` actually runs

To inspect the generated provisioning script before executing it:

```bash
crashwise setup --dry-run
# Or write to a file:
crashwise setup --output /tmp/crashwise-setup.sh
cat /tmp/crashwise-setup.sh
bash /tmp/crashwise-setup.sh   # only when you've reviewed it
```

The script is `set -euo pipefail` and only invokes the host's package
manager — never `curl | bash` or any third-party installer.
