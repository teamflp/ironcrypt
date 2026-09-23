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
RUN cargo build --locked --release --no-default-features --features "$IRONCRYPT_FEATURES" \
    && strip target/release/ironcrypt \
    && (test ! -f target/release/ironcryptd || strip target/release/ironcryptd)

# Stage 2: Minimal hardened runtime
FROM alpine:3.20

RUN apk add --no-cache ca-certificates \
    && addgroup -S ironcrypt \
    && adduser -S -G ironcrypt -H -D ironcrypt

WORKDIR /app

COPY --from=builder /usr/src/app/target/release/ /tmp/release/
RUN mv /tmp/release/ironcrypt /usr/local/bin/ironcrypt \
    && (test ! -f /tmp/release/ironcryptd || mv /tmp/release/ironcryptd /usr/local/bin/ironcryptd) \
    && rm -rf /tmp/release \
    && chown -R ironcrypt:ironcrypt /usr/local/bin

# Drop privileges; read-only rootfs recommended at orchestrator layer.
USER ironcrypt

EXPOSE 3000

# Orchestrator should set:
#   --read-only --cap-drop ALL --security-opt no-new-privileges
#   --tmpfs /tmp:rw,noexec,nosuid,size=64m
#   memory/cpu limits as appropriate for the Payment workload.
ENTRYPOINT ["/usr/local/bin/ironcrypt"]
