# syntax=docker/dockerfile:1

# Stage 1: Build static binaries
FROM rust:1.97.1-alpine AS builder

# Define build arguments — Payment examples:
#   --build-arg IRONCRYPT_FEATURES=payment-daemon
# General (includes RSA):
#   --build-arg IRONCRYPT_FEATURES=full
ARG IRONCRYPT_FEATURES="payment-daemon"

# Install build dependencies
RUN apk add --no-cache \
    musl-dev \
    openssl-dev \
    pkgconfig \
    cmake \
    perl \
    make \
    gcc \
    g++ \
    libc-dev \
    linux-headers \
    binutils

ENV RUSTFLAGS=""
ENV PKG_CONFIG_PATH="/usr/lib/pkgconfig:/usr/local/lib/pkgconfig"
ENV OPENSSL_DIR="/usr"
ENV OPENSSL_LIB_DIR="/usr/lib"
ENV OPENSSL_INCLUDE_DIR="/usr/include"

WORKDIR /usr/src/app

COPY Cargo.toml Cargo.lock ./
COPY . .

# musl cannot emit `cdylib`; keep `rlib` so the bins still link without a warning.
RUN sed -i 's/crate-type = \["lib", "cdylib"\]/crate-type = ["rlib"]/' Cargo.toml

# Always pass --no-default-features so Payment builds do not pull rsa-algo.
# payment-daemon emits ironcryptd only; full also emits the ironcrypt CLI.
RUN cargo build --locked --release --no-default-features --features "$IRONCRYPT_FEATURES" \
    && for bin in ironcrypt ironcryptd; do \
         if [ -f "target/release/${bin}" ]; then strip "target/release/${bin}"; fi; \
       done \
    && { [ -f target/release/ironcrypt ] || [ -f target/release/ironcryptd ]; }

# Stage 2: Minimal hardened runtime
FROM alpine:3.20

RUN apk add --no-cache ca-certificates \
    && addgroup -S ironcrypt \
    && adduser -S -G ironcrypt -H -D ironcrypt

WORKDIR /app

COPY --from=builder /usr/src/app/target/release/ /tmp/release/
# Install whichever binaries this feature set produced. The entrypoint
# dispatches `ironcrypt` / `ironcryptd` by name so Compose `command:` still
# selects the daemon when the CLI was not built.
RUN set -eu \
    && if [ -f /tmp/release/ironcrypt ]; then mv /tmp/release/ironcrypt /usr/local/bin/ironcrypt; fi \
    && if [ -f /tmp/release/ironcryptd ]; then mv /tmp/release/ironcryptd /usr/local/bin/ironcryptd; fi \
    && rm -rf /tmp/release \
    && { [ -x /usr/local/bin/ironcrypt ] || [ -x /usr/local/bin/ironcryptd ]; } \
    && printf '%s\n' \
        '#!/bin/sh' \
        'set -eu' \
        'if [ "$#" -gt 0 ] && [ -x "/usr/local/bin/$1" ]; then' \
        '  bin=$1' \
        '  shift' \
        '  exec "/usr/local/bin/$bin" "$@"' \
        'fi' \
        'if [ -x /usr/local/bin/ironcrypt ]; then' \
        '  exec /usr/local/bin/ironcrypt "$@"' \
        'fi' \
        'exec /usr/local/bin/ironcryptd "$@"' \
        > /usr/local/bin/ironcrypt-entrypoint \
    && chmod 755 /usr/local/bin/ironcrypt-entrypoint \
    && chown -R ironcrypt:ironcrypt /usr/local/bin

# Drop privileges; read-only rootfs recommended at orchestrator layer.
USER ironcrypt

EXPOSE 3000

# Orchestrator should set:
#   --read-only --cap-drop ALL --security-opt no-new-privileges
#   --tmpfs /tmp:rw,noexec,nosuid,size=64m
#   memory/cpu limits as appropriate for the Payment workload.
ENTRYPOINT ["/usr/local/bin/ironcrypt-entrypoint"]
