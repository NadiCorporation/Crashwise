# ──────────────────────────────────────────────────────────────────────────────
# CrashWise — Multi-Stage Production Container (Operation Megabits)
# ──────────────────────────────────────────────────────────────────────────────

# ── Stage 1: Build Web Command Center ──
FROM node:20-slim AS web-builder
WORKDIR /app/web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

# ── Stage 2: Build Rust Core Binary ──
FROM rust:1.80-bullseye AS rust-builder
WORKDIR /app
RUN apt-get update && apt-get install -y clang cmake make libclang-dev
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/
RUN cargo build --release --bin crashwise

# ── Stage 3: Minimal Runtime Container ──
FROM debian:bookworm-slim AS runtime
WORKDIR /app

# Install security research dependencies & compilers
RUN apt-get update && apt-get install -y --no-install-recommends \
    clang \
    clang++ \
    cmake \
    make \
    meson \
    git \
    ca-certificates \
    libsqlite3-0 \
    && rm -rf /var/lib/apt/lists/*

# Copy built artifacts
COPY --from=rust-builder /app/target/release/crashwise /usr/local/bin/crashwise
COPY --from=web-builder /app/web/out /app/web-ui

ENV CRASHWISE_WORKDIR=/tmp/crashwise \
    CRASHWISE_API_HOST=0.0.0.0 \
    CRASHWISE_API_PORT=8000

EXPOSE 8000

ENTRYPOINT ["crashwise"]
CMD ["server", "--host", "0.0.0.0", "--port", "8000"]
