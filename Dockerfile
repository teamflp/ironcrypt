# syntax=docker/dockerfile:1

# Stage 1: Build static MUSL binaries
FROM rust:1.81.0-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    musl-tools \
    build-essential \
    pkg-config \
    libssl-dev \
    cmake \
    perl \
    binutils \
    lld \
 && rm -rf /var/lib/apt/lists/*

# Enable MUSL target
RUN rustup target add x86_64-unknown-linux-musl

WORKDIR /usr/src/app

# Copy manifests and cargo config first to leverage layer caching
COPY Cargo.toml Cargo.lock ./
COPY .cargo/ .cargo/

# Create minimal sources so cargo can resolve and cache dependencies
RUN mkdir -p src/bin && \
    printf "" > src/lib.rs && \
    echo "fn main() {}" > src/main.rs && \
    echo "fn main() {}" > src/bin/daemon.rs

# Build dependencies (and possibly simple bin) to warm cache
RUN cargo build --locked --release --target x86_64-unknown-linux-musl

# Remove dummy sources
RUN rm -rf src

# Copy the real project sources
COPY . .

# Build release binaries for MUSL target and strip them to reduce size
RUN cargo build --locked --release --target x86_64-unknown-linux-musl && \
    strip target/x86_64-unknown-linux-musl/release/ironcrypt && \
    strip target/x86_64-unknown-linux-musl/release/ironcryptd

# Stage 2: Minimal runtime image
FROM alpine:3.20

# Certificates for HTTPS (AWS/Azure/GCP, etc.)
RUN apk add --no-cache ca-certificates

WORKDIR /usr/local/bin

# Copy both binaries from the builder stage
COPY --from=builder /usr/src/app/target/x86_64-unknown-linux-musl/release/ironcrypt /usr/local/bin/ironcrypt
COPY --from=builder /usr/src/app/target/x86_64-unknown-linux-musl/release/ironcryptd /usr/local/bin/ironcryptd

# Default port for the daemon
EXPOSE 3000

# Default command runs the CLI; to run daemon use: `docker run ... ironcryptd -v v1 -d keys -p 3000`
ENTRYPOINT ["/usr/local/bin/ironcrypt"]
