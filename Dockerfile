# syntax=docker/dockerfile:1

# Stage 1: Build static MUSL binaries
FROM rust:1.81.0-bookworm AS builder

# Define build arguments
ARG IRONCRYPT_FEATURES="full"

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

# Enable MUSL target and set the linker for it
RUN rustup target add x86_64-unknown-linux-musl
ENV CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=musl-gcc

WORKDIR /usr/src/app

# Copy manifests and cargo config first to leverage layer caching
COPY Cargo.toml Cargo.lock ./
COPY .cargo/ .cargo/

# Create minimal sources so cargo can resolve and cache dependencies
# This is conditional on features so that the dependency build is cached correctly
# for a given set of features.
RUN mkdir -p src/bin && \
    printf "" > src/lib.rs && \
    if [ -n "$(echo $IRONCRYPT_FEATURES | grep 'cli')" ]; then echo "fn main() {}" > src/main.rs; fi && \
    if [ -n "$(echo $IRONCRYPT_FEATURES | grep 'daemon')" ]; then echo "fn main() {}" > src/bin/daemon.rs; fi

# Build dependencies to warm cache
# We use --no-default-features and pass the specific features to build.
RUN cargo build --locked --release --target x86_64-unknown-linux-musl --no-default-features --features "$IRONCRYPT_FEATURES"

# Remove dummy sources
RUN rm -rf src

# Copy the real project sources
COPY . .

# Build release binaries for MUSL target and strip them to reduce size
# The strip command for ironcryptd is now conditional.
RUN cargo build --locked --release --target x86_64-unknown-linux-musl --no-default-features --features "$IRONCRYPT_FEATURES" && \
    strip target/x86_64-unknown-linux-musl/release/ironcrypt && \
    if [ -f target/x86_64-unknown-linux-musl/release/ironcryptd ]; then strip target/x86_64-unknown-linux-musl/release/ironcryptd; fi

# Stage 2: Minimal runtime image
FROM alpine:3.20

# Certificates for HTTPS (AWS/Azure/GCP, etc.)
RUN apk add --no-cache ca-certificates

WORKDIR /usr/local/bin

# Copy the release artifacts to a temporary location in the final image
COPY --from=builder /usr/src/app/target/x86_64-unknown-linux-musl/release/ /tmp/release/

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
