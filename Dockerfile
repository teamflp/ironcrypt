FROM rust:1.81.0 AS builder

RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/app

COPY Cargo.toml Cargo.lock ./

RUN mkdir -p src \
 && echo "fn main() {}" > src/main.rs \
 && echo "pub fn lib() {}" > src/lib.rs \
 && cargo build --release \
 && rm -rf src/

COPY . .

RUN cargo build --release --bin ironcrypt

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    libssl-dev \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/app

COPY --from=builder /usr/src/app/target/release/ironcrypt /usr/local/bin/ironcrypt

EXPOSE 9000

CMD ["ironcrypt", "--help"]
