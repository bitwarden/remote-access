# syntax=docker/dockerfile:1

FROM caddy:2.9.1-alpine

ARG VERSION=dev
ENV VERSION=${VERSION}

COPY bw-proxy /usr/local/bin/bw-proxy
COPY Caddyfile /etc/caddy/Caddyfile
COPY entrypoint.sh /usr/local/bin/entrypoint.sh

ENV BIND_ADDR=127.0.0.1:9090
ENV RUST_LOG=info

EXPOSE 8080
CMD ["entrypoint.sh"]
