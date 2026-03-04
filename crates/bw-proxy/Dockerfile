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

RUN cargo build --release -p bw-proxy

# --- Runtime stage ---
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3 \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Caddy (static binary)
ARG CADDY_VERSION=2.9.1
RUN curl -fsSL "https://github.com/caddyserver/caddy/releases/download/v${CADDY_VERSION}/caddy_${CADDY_VERSION}_linux_amd64.tar.gz" \
    | tar xz -C /usr/local/bin caddy \
    && apt-get purge -y curl && apt-get autoremove -y

RUN groupadd --system bwproxy && useradd --system --gid bwproxy --create-home bwproxy

COPY --from=builder /build/target/release/bw-proxy /usr/local/bin/bw-proxy
COPY crates/bw-proxy/Caddyfile /etc/caddy/Caddyfile
COPY crates/bw-proxy/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

RUN mkdir -p /home/bwproxy/.config/caddy /home/bwproxy/.local/share/caddy \
    && chown -R bwproxy:bwproxy /home/bwproxy

# bw-proxy listens on localhost; Caddy reverse-proxies on 0.0.0.0:8080
ENV BIND_ADDR=127.0.0.1:9090
ENV RUST_LOG=info
ENV HOME=/home/bwproxy

EXPOSE 8080

USER bwproxy

CMD ["entrypoint.sh"]
