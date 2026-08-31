# ──────────────────────────────────────────────────────────────────────────────
# CrashWise — Production Dockerfile
# Multi-stage build optimised for size and security.
# ──────────────────────────────────────────────────────────────────────────────

# ═══════════════════════════════════════════════════════════════════════════════
# Stage 1 — Builder (heavy dependencies, compilation)
# ═══════════════════════════════════════════════════════════════════════════════
FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim AS builder

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=0 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install system build deps (needed for some Python packages).
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libffi-dev \
    git \
    && rm -rf /var/lib/apt/lists/*

# Copy dependency definitions first for layer caching.
COPY pyproject.toml uv.lock LICENSE README.md ./
# Install production dependencies into a virtual environment.
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --no-install-project

# Copy source code and install the project itself.
COPY crashwise/ ./crashwise/
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev

# ═══════════════════════════════════════════════════════════════════════════════
# Stage 2 — Runtime (minimal image, no build tools)
# ═══════════════════════════════════════════════════════════════════════════════
FROM python:3.11-slim-bookworm AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/app/.venv/bin:$PATH"

WORKDIR /app

# Install only runtime system deps.
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for security.
RUN groupadd -r crashwise && useradd -r -g crashwise crashwise

# Copy the built virtual environment from the builder stage.
COPY --from=builder --chown=crashwise:crashwise /app/.venv /app/.venv
COPY --from=builder --chown=crashwise:crashwise /app/crashwise /app/crashwise

# Switch to non-root user.
USER crashwise

# Health check for container orchestrators.
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python -c "import crashwise; print(crashwise.__version__)" || exit 1

# Default: show help (override per-service in docker-compose).
CMD ["crashwise", "--help"]
