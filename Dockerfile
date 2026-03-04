# syntax=docker/dockerfile:1

# --- Builder stage ---
FROM rust:1.93-slim-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Optional: install extra CA cert (e.g. Zscaler) for corporate proxy environments.
# Create an empty file if not needed: touch extra-root-ca.crt
COPY extra-root-ca.crt /tmp/extra-root-ca.crt
RUN if [ -s /tmp/extra-root-ca.crt ]; then \
      cp /tmp/extra-root-ca.crt /usr/local/share/ca-certificates/extra-root-ca.crt && \
      update-ca-certificates; \
    fi

WORKDIR /build

COPY Cargo.toml Cargo.lock ./
COPY crates crates

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    cargo build --release -p bw-proxy

# --- Runtime stage ---
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Run as non-root user
RUN groupadd --system bwproxy && useradd --system --gid bwproxy bwproxy

COPY --from=builder /build/target/release/bw-proxy /usr/local/bin/bw-proxy

# Containers must bind all interfaces, not 127.0.0.1
ENV BIND_ADDR=0.0.0.0:8080
ENV RUST_LOG=info

EXPOSE 8080

USER bwproxy

CMD ["bw-proxy"]
