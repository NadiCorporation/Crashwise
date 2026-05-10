# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""System Sentinel — diagnostic engine for CrashWise host provisioning.

Checks hardware, runtime dependencies, build tools, and service connectivity.
Produces structured results for ``crashwise doctor`` and ``crashwise setup``.
"""

from __future__ import annotations

import asyncio
import os
import platform
import shutil
import subprocess
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

import httpx

from crashwise.core.logging import get_logger

logger = get_logger(__name__)


class CheckStatus(str, Enum):
    """Result of a single sentinel check."""

    OK = "ok"
    WARN = "warn"
    FAIL = "fail"
    SKIP = "skip"


@dataclass(frozen=True)
class CheckResult:
    """Outcome of one sentinel check."""

    name: str
    status: CheckStatus
    message: str
    detail: str = ""
    remediation: str = ""


@dataclass
class SentinelReport:
    """Aggregated report from all sentinel checks."""

    host: str = ""
    platform: str = ""
    checks: list[CheckResult] = field(default_factory=list)

    @property
    def ok_count(self) -> int:
        return sum(1 for c in self.checks if c.status == CheckStatus.OK)

    @property
    def warn_count(self) -> int:
        return sum(1 for c in self.checks if c.status == CheckStatus.WARN)

    @property
    def fail_count(self) -> int:
        return sum(1 for c in self.checks if c.status == CheckStatus.FAIL)

    @property
    def healthy(self) -> bool:
        return self.fail_count == 0

    def by_category(self) -> dict[str, list[CheckResult]]:
        """Group checks by category prefix (e.g. 'hardware.ram')."""
        groups: dict[str, list[CheckResult]] = {}
        for check in self.checks:
            cat = check.name.split(".")[0] if "." in check.name else "misc"
            groups.setdefault(cat, []).append(check)
        return groups


# ── Helpers ──────────────────────────────────────────────────────────────────


def _run(cmd: list[str], timeout: float = 5.0) -> tuple[int, str, str]:
    """Run a shell command and return (rc, stdout, stderr)."""
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
    except FileNotFoundError:
        return 127, "", f"command not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return -1, "", "timed out"


def _which(name: str) -> str | None:
    """Find executable path or None."""
    return shutil.which(name)


def _is_root() -> bool:
    """True when the current process runs as UID 0."""
    try:
        return os.geteuid() == 0
    except AttributeError:  # pragma: no cover - non-POSIX
        return False


def _sudo_prefix() -> str:
    """Return ``'sudo '`` when the current user is non-root and ``sudo``
    is on PATH; otherwise an empty string.

    The Linux-native finalisation requires every install / systemctl /
    usermod command emitted by the Sentinel to honour the caller's
    privilege level: root invocations should not get a stray ``sudo``
    (it can fail in minimal containers), while non-root users should
    not be presented with raw privileged commands they cannot copy-paste.
    """
    if _is_root():
        return ""
    if not _which("sudo"):
        return ""
    return "sudo "


def _install_hint(distro: str, packages: list[str]) -> str:
    """Compose a one-line install suggestion for the given distro+pkgs."""
    pkgs = " ".join(packages)
    sudo = _sudo_prefix()
    if distro == "arch":
        return f"{sudo}pacman -S --needed {pkgs}"
    if distro == "fedora":
        return f"{sudo}dnf install -y {pkgs}"
    return f"{sudo}apt-get install -y {pkgs}"


# ── Distribution detection (Phase 21 / Linux Native finalisation) ────────────

_DISTRO_OVERRIDE: str | None = None  # test hook; never set in production


@dataclass(frozen=True)
class DistroInfo:
    """Normalised host-distribution identity.

    ``family`` is the package-manager family CrashWise dispatches on
    (``arch`` / ``debian`` / ``fedora`` / ``unknown``).  ``id_`` and
    ``pretty_name`` come straight from ``/etc/os-release`` so callers
    can render user-friendly diagnostics ("Detected: Ubuntu 24.04
    LTS") without re-reading the file.
    """

    family: str
    id_: str = ""
    pretty_name: str = ""
    version_id: str = ""

    @property
    def is_arch(self) -> bool:
        return self.family == "arch"

    @property
    def is_debian(self) -> bool:
        return self.family == "debian"

    @property
    def is_fedora(self) -> bool:
        return self.family == "fedora"


class DistroDetector:
    """Robust distro detector backed by ``/etc/os-release``.

    The detector is an instance method object rather than a free
    function so callers can stub it out in tests, inject overrides for
    container builds (``crashwise doctor --distro arch``), and cache
    the parse result for the lifetime of a CLI invocation.
    """

    def __init__(self, *, override: str | None = None) -> None:
        self._override = override
        self._cached: DistroInfo | None = None

    def detect(self) -> DistroInfo:
        """Return a :class:`DistroInfo` for the current host (cached).

        Resolution order:
        1. Explicit ``override`` passed to the constructor.
        2. Module-level ``_DISTRO_OVERRIDE`` (legacy test hook).
        3. ``/etc/os-release`` parse.
        4. ``unknown`` family.
        """
        if self._cached is not None:
            return self._cached

        forced = self._override or _DISTRO_OVERRIDE
        if forced:
            family = self._normalise(forced, forced)
            self._cached = DistroInfo(family=family, id_=forced)
            return self._cached

        data = self._parse_os_release()
        id_ = data.get("ID", "").lower()
        id_like = data.get("ID_LIKE", "").lower()
        family = self._normalise(id_, id_like)
        self._cached = DistroInfo(
            family=family,
            id_=id_,
            pretty_name=data.get("PRETTY_NAME", ""),
            version_id=data.get("VERSION_ID", ""),
        )
        return self._cached

    @staticmethod
    def _parse_os_release() -> dict[str, str]:
        try:
            with open("/etc/os-release") as fh:
                data: dict[str, str] = {}
                for line in fh:
                    if "=" not in line:
                        continue
                    key, _, value = line.partition("=")
                    data[key.strip()] = value.strip().strip('"').strip("'")
                return data
        except FileNotFoundError:
            return {}

    @staticmethod
    def _normalise(id_: str, id_like: str) -> str:
        id_ = id_.lower()
        id_like = id_like.lower()
        if id_ == "arch" or "arch" in id_like or "manjaro" in id_ or "endeavouros" in id_:
            return "arch"
        if (
            id_ in {"debian", "ubuntu", "linuxmint", "pop", "kali", "raspbian"}
            or "debian" in id_like
            or "ubuntu" in id_like
        ):
            return "debian"
        if (
            id_ in {"fedora", "rhel", "centos", "rocky", "almalinux", "amzn"}
            or "fedora" in id_like
            or "rhel" in id_like
        ):
            return "fedora"
        return "unknown"


# Module-level singleton — safe to share because parsing is idempotent.
_default_detector = DistroDetector()


def _detect_distro() -> str:
    """Return ``'arch'``, ``'debian'``, ``'fedora'``, or ``'unknown'``.

    Backwards-compatible thin wrapper around :class:`DistroDetector`
    for callers that only need the family string.  Honours
    ``_DISTRO_OVERRIDE`` so existing unit tests continue to work.

    Note: this entry point intentionally does **not** consult the
    module-level cache — tests use ``monkeypatch`` to swap in fake
    ``open`` and ``_DISTRO_OVERRIDE`` on a per-test basis, and would
    otherwise be served stale answers from a singleton populated by an
    earlier test.
    """
    return DistroDetector(override=_DISTRO_OVERRIDE).detect().family


def detect_distro() -> DistroInfo:
    """Public, structured distro lookup.  Use this in new code.

    Uses the module-level singleton cache for production callers (CLI,
    workflow). Override-aware tests should call ``DistroDetector`` directly
    or set ``_DISTRO_OVERRIDE`` before invoking ``_detect_distro``.
    """
    if _DISTRO_OVERRIDE:
        return DistroDetector(override=_DISTRO_OVERRIDE).detect()
    return _default_detector.detect()


def _parse_meminfo_kb(key: str) -> int | None:
    """Parse /proc/meminfo for a key (e.g. 'MemTotal')."""
    try:
        with open("/proc/meminfo") as fh:
            for line in fh:
                if line.startswith(key):
                    val = line.split(":")[1].strip().split()[0]
                    return int(val)
    except (FileNotFoundError, ValueError, IndexError):
        pass
    return None


def _get_total_ram_gb() -> float | None:
    """Return total RAM in GB (Linux only)."""
    kb = _parse_meminfo_kb("MemTotal")
    if kb is not None:
        return round(kb / (1024 * 1024), 2)
    return None


def _get_cpu_cores() -> int | None:
    """Return logical CPU core count."""
    try:
        return os.cpu_count()
    except Exception:
        return None


def _get_free_disk_gb(path: Path = Path("/")) -> float | None:
    """Return free disk space in GB."""
    try:
        st = os.statvfs(path)
        return round((st.f_bavail * st.f_frsize) / (1024 ** 3), 2)
    except OSError:
        return None


# ── Check Functions ──────────────────────────────────────────────────────────


def check_hardware_ram(min_gb: float = 8.0) -> CheckResult:
    """Check total system RAM."""
    total = _get_total_ram_gb()
    if total is None:
        return CheckResult(
            name="hardware.ram",
            status=CheckStatus.SKIP,
            message="Could not detect RAM (non-Linux?).",
            remediation="Ensure at least 8 GB RAM for fuzzing.",
        )
    if total >= min_gb:
        return CheckResult(
            name="hardware.ram",
            status=CheckStatus.OK,
            message=f"{total:.1f} GB RAM detected.",
        )
    return CheckResult(
        name="hardware.ram",
        status=CheckStatus.WARN,
        message=f"Only {total:.1f} GB RAM detected (recommended: {min_gb:.0f} GB).",
        remediation="Add more RAM or reduce parallel fuzzing jobs.",
    )


def check_hardware_cpu(min_cores: int = 4) -> CheckResult:
    """Check CPU core count."""
    cores = _get_cpu_cores()
    if cores is None:
        return CheckResult(
            name="hardware.cpu",
            status=CheckStatus.SKIP,
            message="Could not detect CPU cores.",
        )
    if cores >= min_cores:
        return CheckResult(
            name="hardware.cpu",
            status=CheckStatus.OK,
            message=f"{cores} logical cores detected.",
        )
    return CheckResult(
        name="hardware.cpu",
        status=CheckStatus.WARN,
        message=f"Only {cores} cores detected (recommended: {min_cores}).",
        remediation="Reduce worker concurrency or use a machine with more cores.",
    )


def check_hardware_disk(min_free_gb: float = 50.0) -> CheckResult:
    """Check available disk space."""
    free = _get_free_disk_gb()
    if free is None:
        return CheckResult(
            name="hardware.disk",
            status=CheckStatus.SKIP,
            message="Could not detect disk space.",
        )
    if free >= min_free_gb:
        return CheckResult(
            name="hardware.disk",
            status=CheckStatus.OK,
            message=f"{free:.1f} GB free disk space.",
        )
    return CheckResult(
        name="hardware.disk",
        status=CheckStatus.WARN,
        message=f"Only {free:.1f} GB free (recommended: {min_free_gb:.0f} GB).",
        remediation="Free up disk space or mount a larger volume.",
    )


def _user_can_reach_docker_socket() -> bool:
    """Return True when the *current* process can talk to the Docker socket.

    Uses access(2) on ``/var/run/docker.sock`` with read+write bits.  This
    is independent of group-membership lookup: if the user was added to
    the ``docker`` group in this same shell, their *effective* groups
    are still stale and the socket will be unreachable until logout/login
    or ``newgrp docker``.  access(2) reflects exactly that — what the
    running process can actually do, right now.
    """
    sock = Path("/var/run/docker.sock")
    if not sock.exists():
        return False
    try:
        return os.access(sock, os.R_OK | os.W_OK)
    except OSError:
        return False


def _user_in_docker_group() -> bool:
    """Return True when the current user appears in ``/etc/group``'s docker line.

    This is a *configuration* check — it reads /etc/group directly and
    therefore picks up additions made in the current session that the
    kernel's effective-group set hasn't yet inherited.  We use this in
    combination with :func:`_user_can_reach_docker_socket` to distinguish
    "needs to log out" from "not in group at all".
    """
    try:
        import grp

        user = os.environ.get("USER") or os.environ.get("LOGNAME") or ""
        if not user:
            return False
        if os.geteuid() == 0:
            return True  # root always wins
        docker_grp = grp.getgrnam("docker")
        return user in docker_grp.gr_mem
    except (KeyError, ImportError, OSError):
        return False


def check_runtime_docker() -> CheckResult:
    """Check Docker daemon availability with precise failure diagnosis.

    Three distinct failure modes that ``crashwise doctor`` must
    distinguish (each has a *different* remediation):

    1. **Docker not installed.**  CLI binary missing from ``$PATH``.
       → install the distro package.
    2. **Daemon down.**  CLI present, ``/var/run/docker.sock`` missing or
       process can't even reach the socket file.
       → ``systemctl start docker``.
    3. **Permission denied (group-not-applied).**  CLI present, socket
       present, but the EUID-bound socket connect returns EACCES.  This
       fires in two sub-cases that *look identical* in the error string
       but require *different* fixes:
       a. User is genuinely not in the ``docker`` group → run
          ``usermod -aG docker $USER`` then re-login.
       b. User WAS just added to the group (e.g. by ``crashwise setup``)
          but the current shell still holds the old credential set →
          log out / log back in, or ``newgrp docker`` for the current
          shell.  This is the case Yahya hit on Ubuntu 24.04.
    """
    rc, out, err = _run(["docker", "version", "--format", "{{.Server.Version}}"])
    if rc == 0 and out:
        return CheckResult(
            name="runtime.docker",
            status=CheckStatus.OK,
            message=f"Docker {out} is running.",
        )

    distro = _detect_distro()
    sudo = _sudo_prefix()

    # ── 1. CLI missing entirely. ─────────────────────────────────────
    if not _which("docker"):
        pkgs = _CHECK_PACKAGES_BY_DISTRO.get(
            distro, _CHECK_PACKAGES_BY_DISTRO["debian"]
        ).get("runtime.docker", ["docker"])
        return CheckResult(
            name="runtime.docker",
            status=CheckStatus.FAIL,
            message="Docker is not installed.",
            remediation=f"Install Docker: {_install_hint(distro, pkgs)}",
        )

    # ── 2. Permission denied → group / session diagnosis. ────────────
    err_lower = (err or "").lower()
    is_permission_denied = (
        "permission denied" in err_lower
        or "permission denied" in (out or "").lower()
    )
    if is_permission_denied:
        in_group_config = _user_in_docker_group()
        socket_reachable = _user_can_reach_docker_socket()
        user = os.environ.get("USER") or os.environ.get("LOGNAME") or "$USER"

        if in_group_config and not socket_reachable:
            # The Ubuntu 24.04 case: usermod -aG already ran, the
            # /etc/group line shows the user, but the running shell
            # still has the pre-usermod credential set.
            return CheckResult(
                name="runtime.docker",
                status=CheckStatus.FAIL,
                message=(
                    f"Docker daemon is running but your current SHELL SESSION "
                    "doesn't have docker-group permissions yet."
                ),
                detail=(
                    f"User {user!r} IS in the docker group on disk "
                    "(/etc/group), but the kernel's effective groups for "
                    "this process were inherited before the group was "
                    "applied. Linux only re-evaluates group membership at "
                    "login."
                ),
                remediation=(
                    "Log out and log back in (or close this terminal and "
                    "open a new one). For a single-shell quick fix: run "
                    "'newgrp docker' — this spawns a new shell where the "
                    "docker group is active."
                ),
            )

        if not in_group_config:
            return CheckResult(
                name="runtime.docker",
                status=CheckStatus.FAIL,
                message=(
                    f"Docker daemon is running but user {user!r} is not in "
                    "the docker group."
                ),
                detail=err or out,
                remediation=(
                    f"{sudo}usermod -aG docker {user}  &&  "
                    "log out / log back in (the group only takes effect on a "
                    "fresh login session)."
                ),
            )

        # In-group AND socket reachable but ``docker version`` still
        # failed — unusual; surface raw stderr so the user can debug.
        return CheckResult(
            name="runtime.docker",
            status=CheckStatus.FAIL,
            message="Docker permission error (unexpected — file an issue).",
            detail=err or out,
            remediation=(
                f"Try: {sudo}systemctl restart docker, then retry. "
                "If this persists, paste the detail line into an issue."
            ),
        )

    # ── 3. Daemon down. ──────────────────────────────────────────────
    return CheckResult(
        name="runtime.docker",
        status=CheckStatus.FAIL,
        message="Docker CLI found but daemon is not responding.",
        detail=err or out,
        remediation=(
            f"Start Docker: {sudo}systemctl start docker  "
            f"(enable on boot: {sudo}systemctl enable docker)."
        ),
    )


def check_runtime_docker_compose() -> CheckResult:
    """Check Docker Compose availability.

    Strongly prefers the modern v2 plugin (``docker compose``) over the
    legacy Python v1 standalone (``docker-compose``).  v1 is incompatible
    with current Docker Engines (KeyError: 'ContainerConfig' when
    recreating containers — see docker/compose#9229) and will tear down
    the entire stack on the first ``up -d`` after an image rebuild.

    Resolution order:
      1. v2 plugin works → OK.
      2. v2 plugin missing but v1 standalone works → FAIL with clear
         migration instructions.  We deliberately do NOT report this as
         a soft warning because it WILL break the user's first
         ``docker compose up -d``.
      3. Neither works → FAIL with install instructions.
    """
    # 1. Modern v2 plugin.
    rc, out, _ = _run(["docker", "compose", "version"])
    if rc == 0:
        return CheckResult(
            name="runtime.docker-compose",
            status=CheckStatus.OK,
            message=f"Docker Compose v2 plugin available ({out.splitlines()[0]}).",
        )

    distro = _detect_distro()
    sudo = _sudo_prefix()

    # 2. Legacy v1 — actively dangerous.
    rc_v1, out_v1, _ = _run(["docker-compose", "--version"])
    if rc_v1 == 0:
        version_line = out_v1.splitlines()[0] if out_v1 else "unknown"
        # Legacy v1 reports "docker-compose version 1.x.x".
        is_v1 = "version 1." in version_line.lower()
        if is_v1:
            if distro == "arch":
                migrate_cmd = (
                    f"{sudo}pacman -Syu docker docker-compose docker-buildx"
                )
            elif distro == "fedora":
                migrate_cmd = (
                    f"{sudo}dnf install -y docker-compose-plugin && "
                    f"{sudo}dnf remove -y python3-docker-compose"
                )
            else:  # debian / ubuntu
                migrate_cmd = (
                    f"{sudo}apt-get remove -y docker-compose && "
                    f"{sudo}apt-get install -y docker-compose-plugin"
                )
            return CheckResult(
                name="runtime.docker-compose",
                status=CheckStatus.FAIL,
                message=(
                    f"Only legacy Compose v1 found ({version_line}). "
                    "v1 is incompatible with current Docker Engines and "
                    "crashes with 'KeyError: ContainerConfig' (see "
                    "docker/compose#9229)."
                ),
                remediation=(
                    f"Install the v2 plugin: {migrate_cmd}  "
                    "Then verify with `docker compose version` (note the SPACE)."
                ),
            )
        # docker-compose binary exists but version line is unfamiliar —
        # treat as OK on the assumption it's a v2-compatible standalone.
        return CheckResult(
            name="runtime.docker-compose",
            status=CheckStatus.OK,
            message=f"Docker Compose available ({version_line}).",
        )

    # 3. Nothing works.
    pkgs = _CHECK_PACKAGES_BY_DISTRO.get(
        distro, _CHECK_PACKAGES_BY_DISTRO["debian"]
    ).get("runtime.docker-compose", ["docker-compose-plugin"])
    return CheckResult(
        name="runtime.docker-compose",
        status=CheckStatus.FAIL,
        message="Docker Compose not found.",
        remediation=f"Install: {_install_hint(distro, pkgs)}",
    )


def check_runtime_python(min_major: int = 3, min_minor: int = 11) -> CheckResult:
    """Check Python version."""
    major, minor, *_ = platform.python_version_tuple()
    ver = f"{major}.{minor}"
    if int(major) > min_major or (int(major) == min_major and int(minor) >= min_minor):
        return CheckResult(
            name="runtime.python",
            status=CheckStatus.OK,
            message=f"Python {ver} (>= {min_major}.{min_minor}).",
        )
    return CheckResult(
        name="runtime.python",
        status=CheckStatus.FAIL,
        message=f"Python {ver} is too old (need >= {min_major}.{min_minor}).",
        remediation="Install Python 3.11+ via pyenv or apt.",
    )


def _build_remediation(check_name: str, default_pkgs: list[str]) -> str:
    """Resolve the install hint for a given build-tool check.

    Looks up the per-distro package list, falling back to ``default_pkgs``
    when the host distro has no entry, and prefixes ``sudo`` only when
    needed.
    """
    distro = _detect_distro()
    pkgs = _CHECK_PACKAGES_BY_DISTRO.get(distro, _CHECK_PACKAGES_BY_DISTRO["debian"]).get(
        check_name, default_pkgs
    )
    return _install_hint(distro, pkgs)


def check_build_cmake() -> CheckResult:
    """Check CMake availability."""
    rc, out, _ = _run(["cmake", "--version"])
    if rc == 0:
        ver = out.splitlines()[0] if out else "unknown"
        return CheckResult(
            name="build.cmake",
            status=CheckStatus.OK,
            message=f"CMake found ({ver}).",
        )
    return CheckResult(
        name="build.cmake",
        status=CheckStatus.FAIL,
        message="CMake not found.",
        remediation=f"Install: {_build_remediation('build.cmake', ['cmake'])}",
    )


def check_build_clang() -> CheckResult:
    """Check Clang availability."""
    rc, out, _ = _run(["clang", "--version"])
    if rc == 0:
        ver = out.splitlines()[0] if out else "unknown"
        return CheckResult(
            name="build.clang",
            status=CheckStatus.OK,
            message=f"Clang found ({ver}).",
        )
    return CheckResult(
        name="build.clang",
        status=CheckStatus.FAIL,
        message="Clang not found.",
        remediation=f"Install: {_build_remediation('build.clang', ['clang'])}",
    )


def check_build_gcc() -> CheckResult:
    """Check GCC availability."""
    rc, out, _ = _run(["gcc", "--version"])
    if rc == 0:
        ver = out.splitlines()[0] if out else "unknown"
        return CheckResult(
            name="build.gcc",
            status=CheckStatus.OK,
            message=f"GCC found ({ver}).",
        )
    return CheckResult(
        name="build.gcc",
        status=CheckStatus.FAIL,
        message="GCC not found.",
        remediation=f"Install: {_build_remediation('build.gcc', ['gcc'])}",
    )


def check_build_llvm() -> CheckResult:
    """Check LLVM development tools.

    Probes ``llvm-config`` (Arch / Fedora / generic install) FIRST, then
    falls back to Debian's versioned binaries (``llvm-config-19`` … ``-15``).
    Phase 21: includes ``-19`` to cover current Arch rolling release.
    """
    # Generic / Arch / Fedora installations expose plain ``llvm-config``.
    rc, out, _ = _run(["llvm-config", "--version"])
    if rc == 0 and out:
        return CheckResult(
            name="build.llvm",
            status=CheckStatus.OK,
            message=f"LLVM {out.strip()} found.",
        )
    # Debian/Ubuntu ship versioned binaries.
    for suffix in ["-19", "-18", "-17", "-16", "-15"]:
        rc2, out2, _ = _run([f"llvm-config{suffix}", "--version"])
        if rc2 == 0:
            return CheckResult(
                name="build.llvm",
                status=CheckStatus.OK,
                message=f"LLVM {out2.strip()} found (via llvm-config{suffix}).",
            )
    return CheckResult(
        name="build.llvm",
        status=CheckStatus.FAIL,
        message="LLVM development tools not found.",
        remediation=f"Install: {_build_remediation('build.llvm', ['llvm-dev'])}",
    )


def check_build_afl() -> CheckResult:
    """Check AFL++ availability.

    On Arch the canonical package (``aflplusplus``) lives in the AUR.
    We detect a configured AUR helper (``yay`` or ``paru``) and suggest
    the matching command; otherwise we point the user at the AUR
    page and gracefully fall back to the Dockerised worker which
    ships AFL++ pre-installed.

    Note on detection: AFL++ has no ``--version`` flag.  ``-V`` is the
    fuzz-duration option (requires a seconds argument) and exits 1
    when called without one — using it for detection (the original
    behaviour) reported "not found" even when AFL++ was correctly
    installed.  We use ``shutil.which`` for presence and a banner
    parse via ``-h`` (which exits 1 but prints the version line) to
    extract the actual version.
    """
    afl_path = _which("afl-fuzz")
    if afl_path:
        # ``afl-fuzz -h`` prints e.g.
        # "afl-fuzz++4.21c based on afl by Michal Zalewski ..."
        # then exits with rc=1.  We parse the *banner* line (the one
        # that mentions "based on afl by ..." or starts with
        # "afl-fuzz++") to confirm the binary actually loaded.  If we
        # only see dynamic-loader errors (e.g. "error while loading
        # shared libraries") the install is broken — surface as WARN.
        _, out, err = _run(["afl-fuzz", "-h"], timeout=3.0)
        combined = "\n".join(filter(None, (out, err)))
        banner_line = next(
            (
                line.strip()
                for line in combined.splitlines()
                if "based on afl by" in line.lower()
                or line.lstrip().lower().startswith("afl-fuzz++")
            ),
            "",
        )
        if banner_line:
            return CheckResult(
                name="build.afl++",
                status=CheckStatus.OK,
                message=f"AFL++ found ({banner_line}).",
            )
        # Binary is on PATH but failed to print a banner — most likely a
        # broken dynamic link (libpython mismatch is a common one).
        first_err = next(
            (line for line in combined.splitlines() if line.strip()),
            "(no output)",
        )
        return CheckResult(
            name="build.afl++",
            status=CheckStatus.WARN,
            message=f"AFL++ binary present at {afl_path} but failed to load.",
            detail=first_err,
            remediation=(
                "The afl-fuzz binary is on PATH but cannot run — usually "
                "a missing shared library.  Reinstall the distro package, "
                "or skip the host install and use the Docker worker which "
                "ships a known-good AFL++."
            ),
        )
    distro = _detect_distro()
    sudo = _sudo_prefix()
    if distro == "arch":
        helper = _which("yay") or _which("paru")
        if helper:
            helper_name = Path(helper).name
            remediation = (
                f"Install via AUR helper: {helper_name} -S aflplusplus  "
                "(or skip — Docker worker ships AFL++)."
            )
        else:
            remediation = (
                "AFL++ is in the AUR.  Install an AUR helper first "
                f"({sudo}pacman -S --needed base-devel git && "
                "git clone https://aur.archlinux.org/yay.git && "
                "cd yay && makepkg -si), then 'yay -S aflplusplus'.  "
                "Alternatively the Docker worker ships AFL++."
            )
    else:
        pkgs = _CHECK_PACKAGES_BY_DISTRO.get(
            distro, _CHECK_PACKAGES_BY_DISTRO["debian"]
        ).get("build.afl++", ["afl++"])
        remediation = (
            f"Install: {_install_hint(distro, pkgs)}  "
            "(or skip — Docker worker ships AFL++)."
        )
    return CheckResult(
        name="build.afl++",
        status=CheckStatus.WARN,
        message="AFL++ not found on host.",
        remediation=remediation,
    )


def check_build_libfuzzer() -> CheckResult:
    """Check LibFuzzer availability (via clang -fsanitize=fuzzer)."""
    rc, out, err = _run([
        "clang", "-fsanitize=fuzzer", "-x", "c", "-",
    ], timeout=3.0)
    # clang will fail because stdin is empty, but we just check it recognises the flag
    if "unrecognized" in (err + out).lower() or "unknown" in (err + out).lower():
        return CheckResult(
            name="build.libfuzzer",
            status=CheckStatus.WARN,
            message="LibFuzzer support not detected in Clang.",
            remediation="Install clang with fuzzer support or use Docker worker.",
        )
    return CheckResult(
        name="build.libfuzzer",
        status=CheckStatus.OK,
        message="LibFuzzer support detected in Clang.",
    )


async def check_service_temporal(
    host: str = "localhost",
    port: int = 7233,
    timeout: float = 3.0,
) -> CheckResult:
    """Check Temporal server connectivity."""
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            # Temporal gRPC health check isn't HTTP; try the Web UI port as proxy
            resp = await client.get(f"http://{host}:8233")
            if resp.status_code < 500:
                return CheckResult(
                    name="service.temporal",
                    status=CheckStatus.OK,
                    message=f"Temporal Web UI reachable at {host}:8233.",
                )
    except Exception as exc:
        pass
    return CheckResult(
        name="service.temporal",
        status=CheckStatus.WARN,
        message=f"Temporal server not reachable at {host}:{port}.",
        remediation="Start Temporal:  docker compose up temporal",
    )


async def check_service_redis(
    host: str = "localhost",
    port: int = 6379,
    timeout: float = 3.0,
) -> CheckResult:
    """Check Redis connectivity."""
    try:
        import redis.asyncio as redis_mod
        r = redis_mod.Redis(host=host, port=port, socket_connect_timeout=timeout)
        await r.ping()
        await r.close()
        return CheckResult(
            name="service.redis",
            status=CheckStatus.OK,
            message=f"Redis reachable at {host}:{port}.",
        )
    except Exception as exc:
        return CheckResult(
            name="service.redis",
            status=CheckStatus.WARN,
            message=f"Redis not reachable at {host}:{port}: {exc}",
            remediation="Start Redis:  docker compose up redis",
        )


async def check_service_llm(
    base_url: str = "http://localhost:11434",
    timeout: float = 3.0,
) -> CheckResult:
    """Check LLM API (Ollama) connectivity."""
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.get(f"{base_url}/api/tags")
            if resp.status_code == 200:
                data = resp.json()
                models = [m.get("name", "?") for m in data.get("models", [])]
                model_list = ", ".join(models[:3]) if models else "no models"
                return CheckResult(
                    name="service.llm",
                    status=CheckStatus.OK,
                    message=f"Ollama reachable. Models: {model_list}",
                )
    except Exception as exc:
        pass
    return CheckResult(
        name="service.llm",
        status=CheckStatus.WARN,
        message=f"LLM API not reachable at {base_url}.",
        remediation="Start Ollama:  ollama serve  (or configure a remote provider)",
    )


# ── Orchestrator ───────────────────────────────────────────────────────────────


async def run_all_checks(
    *,
    temporal_host: str = "localhost",
    temporal_port: int = 7233,
    redis_host: str = "localhost",
    redis_port: int = 6379,
    llm_base_url: str = "http://localhost:11434",
) -> SentinelReport:
    """Run every sentinel check and return an aggregated report."""
    report = SentinelReport(
        host=platform.node(),
        platform=f"{platform.system()} {platform.release()} ({platform.machine()})",
    )

    # Hardware (sync)
    report.checks.extend([
        check_hardware_ram(),
        check_hardware_cpu(),
        check_hardware_disk(),
    ])

    # Runtime (sync)
    report.checks.extend([
        check_runtime_docker(),
        check_runtime_docker_compose(),
        check_runtime_python(),
    ])

    # Build tools (sync)
    report.checks.extend([
        check_build_cmake(),
        check_build_clang(),
        check_build_gcc(),
        check_build_llvm(),
        check_build_afl(),
        check_build_libfuzzer(),
    ])

    # Services (async)
    service_checks = await asyncio.gather(
        check_service_temporal(temporal_host, temporal_port),
        check_service_redis(redis_host, redis_port),
        check_service_llm(llm_base_url),
    )
    report.checks.extend(service_checks)

    return report


# ── Provisioner ──────────────────────────────────────────────────────────────


# Per-distro package mappings. Phase 21 adds Arch (pacman) and Fedora (dnf)
# alongside the existing Debian (apt) mapping.
_CHECK_PACKAGES_BY_DISTRO: dict[str, dict[str, list[str]]] = {
    "debian": {
        # On Ubuntu/Debian the BINARY package is named ``afl++``
        # (verified against packages.ubuntu.com/noble/afl++ — the
        # *source* package is ``aflplusplus`` but ``apt install`` takes
        # the binary name).  Using ``aflplusplus`` here makes apt fail
        # with "Unable to locate package" on every supported release.
        "runtime.docker": ["docker.io", "docker-compose-plugin"],
        "runtime.docker-compose": ["docker-compose-plugin"],
        "build.cmake": ["cmake"],
        "build.clang": ["clang", "lld"],
        "build.gcc": ["gcc", "g++"],
        "build.llvm": ["llvm-dev", "lld"],
        "build.afl++": ["afl++"],
    },
    "arch": {
        # Arch core / extra repo names — pacman.
        "runtime.docker": ["docker", "docker-buildx", "docker-compose"],
        "runtime.docker-compose": ["docker-compose"],
        "build.cmake": ["cmake"],
        "build.clang": ["clang", "lld"],
        # Arch ships C++ as part of `gcc`; no separate g++ package.
        "build.gcc": ["gcc"],
        "build.llvm": ["llvm", "lld"],
        # On Arch, AFL++ lives in the AUR as ``aflplusplus``.
        # ``check_build_afl`` surfaces an AUR-specific remediation.
        # Listed here so ``get_missing_packages`` still names it for
        # display, but the install script special-cases Arch+AUR.
        "build.afl++": ["aflplusplus"],
    },
    "fedora": {
        "runtime.docker": ["docker", "docker-compose-plugin"],
        "runtime.docker-compose": ["docker-compose-plugin"],
        "build.cmake": ["cmake"],
        "build.clang": ["clang", "lld"],
        "build.gcc": ["gcc", "gcc-c++"],
        "build.llvm": ["llvm-devel", "lld"],
        "build.afl++": ["american-fuzzy-lop"],
    },
}

# Back-compat shim: existing imports of ``_CHECK_PACKAGES`` keep working.
_CHECK_PACKAGES = _CHECK_PACKAGES_BY_DISTRO["debian"]


# Per-distro install command templates. ``{sudo}`` is filled in at
# render time by :func:`generate_setup_script` so root-in-container
# installs do not stumble over a missing ``sudo`` binary.
_INSTALL_COMMANDS: dict[str, tuple[str, str]] = {
    "debian": (
        "{sudo}apt-get update -qq",
        "{sudo}apt-get install -y {pkgs}",
    ),
    "arch": (
        "{sudo}pacman -Sy --noconfirm",
        "{sudo}pacman -S --noconfirm --needed {pkgs}",
    ),
    "fedora": (
        "{sudo}dnf -y check-update || true",
        "{sudo}dnf install -y {pkgs}",
    ),
}


def get_missing_packages(
    report: SentinelReport,
    *,
    distro: str | None = None,
) -> list[str]:
    """Return a deduplicated list of packages to install for failed checks.

    Parameters
    ----------
    report:
        Aggregated sentinel report.
    distro:
        Override host distribution detection. ``None`` (default) auto-detects.
    """
    selected = (distro or _detect_distro()).lower()
    table = _CHECK_PACKAGES_BY_DISTRO.get(selected, _CHECK_PACKAGES_BY_DISTRO["debian"])
    packages: set[str] = set()
    for check in report.checks:
        if check.status == CheckStatus.FAIL:
            for pkg in table.get(check.name, []):
                packages.add(pkg)
    return sorted(packages)


# Packages that live in the AUR on Arch — the install script must use
# an AUR helper instead of ``pacman`` for these.
_ARCH_AUR_PACKAGES: frozenset[str] = frozenset({"aflplusplus", "afl++"})


def generate_setup_script(
    packages: list[str],
    *,
    distro: str | None = None,
) -> str:
    """Generate a bash script to install missing packages.

    Picks ``apt``, ``pacman``, or ``dnf`` based on host detection (or the
    explicit ``distro`` override).  ``sudo`` is prepended only when the
    current user is non-root, so the same script works inside Docker
    images that run as root.

    On Arch, AUR-only packages (currently ``aflplusplus``) are split out
    onto a dedicated rail that prefers ``yay`` / ``paru`` and emits a
    clear error if no AUR helper is available.
    """
    if not packages:
        return "# All required packages are already installed.\n"
    selected = (distro or _detect_distro()).lower()
    update_cmd_tmpl, install_cmd_tmpl = _INSTALL_COMMANDS.get(
        selected, _INSTALL_COMMANDS["debian"]
    )
    sudo = _sudo_prefix()

    # Split AUR-only packages out for Arch; keep everything else on the
    # canonical pacman/apt/dnf rail.
    if selected == "arch":
        aur_pkgs = [p for p in packages if p in _ARCH_AUR_PACKAGES]
        repo_pkgs = [p for p in packages if p not in _ARCH_AUR_PACKAGES]
    else:
        aur_pkgs = []
        repo_pkgs = list(packages)

    update_cmd = update_cmd_tmpl.format(sudo=sudo)
    install_cmd = install_cmd_tmpl.format(sudo=sudo, pkgs=" ".join(repo_pkgs))
    label = selected if selected in _INSTALL_COMMANDS else "debian"

    lines = [
        "#!/usr/bin/env bash",
        f"# CrashWise System Provisioner ({label})",
        "# Generated automatically by crashwise setup",
        "",
        "set -euo pipefail",
        "",
        f'echo "[CrashWise] Updating package lists ({label})..."',
        update_cmd,
        "",
    ]
    if repo_pkgs:
        lines.extend(
            [
                'echo "[CrashWise] Installing packages..."',
                install_cmd,
                "",
            ]
        )
    if aur_pkgs:
        aur_list = " ".join(aur_pkgs)
        lines.extend(
            [
                f'echo "[CrashWise] Installing AUR packages: {aur_list}"',
                'AUR_HELPER="$(command -v yay || command -v paru || true)"',
                'if [[ -z "$AUR_HELPER" ]]; then',
                '    echo "[CrashWise] WARNING: no AUR helper (yay/paru) found." >&2',
                '    echo "[CrashWise]          Install one (e.g. yay) and re-run, or"',
                '    echo "[CrashWise]          rely on the Docker worker which ships these tools."',
                "else",
                f'    "$AUR_HELPER" -S --noconfirm --needed {aur_list}',
                "fi",
                "",
            ]
        )
    lines.append('echo "[CrashWise] Setup complete."')
    return "\n".join(lines) + "\n"
