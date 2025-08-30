# syntax=docker/dockerfile:1

# Stage 1: Build static binaries
FROM rust:1.86.0-alpine AS builder

# Define build arguments
ARG IRONCRYPT_FEATURES="full"

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

# Configure linker and OpenSSL paths
ENV RUSTFLAGS=""
ENV PKG_CONFIG_PATH="/usr/lib/pkgconfig:/usr/local/lib/pkgconfig"
ENV OPENSSL_DIR="/usr"
ENV OPENSSL_LIB_DIR="/usr/lib"
ENV OPENSSL_INCLUDE_DIR="/usr/include"

WORKDIR /usr/src/app

# Copy manifests first to leverage layer caching
COPY Cargo.toml Cargo.lock ./

# Copy the real project sources
COPY . .

# Build release binaries and strip them to reduce size
# The strip command for ironcryptd is now conditional.
RUN cargo build --locked --release --no-default-features --features "$IRONCRYPT_FEATURES" && \
    strip target/release/ironcrypt && \
    if [ -f target/release/ironcryptd ]; then strip target/release/ironcryptd; fi

# Stage 2: Minimal runtime image
FROM alpine:3.20

# Certificates for HTTPS (AWS/Azure/GCP, etc.)
RUN apk add --no-cache ca-certificates

WORKDIR /usr/local/bin

# Copy the release artifacts to a temporary location in the final image
COPY --from=builder /usr/src/app/target/release/ /tmp/release/

# Move the main binary and conditionally move the daemon, then cleanup
RUN mv /tmp/release/ironcrypt /usr/local/bin/ironcrypt && \
    if [ -f /tmp/release/ironcryptd ]; then \
        mv /tmp/release/ironcryptd /usr/local/bin/ironcryptd; \
    fi && \
    rm -rf /tmp/release

# Default port for the daemon
EXPOSE 3000

# Default command runs the CLI; to run daemon use: `docker run ... ironcryptd -v v1 -d keys -p 3000`
ENTRYPOINT ["/usr/local/bin/ironcrypt"]
