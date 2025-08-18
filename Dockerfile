# Étape 1 : Construction
FROM rust:1.81.0-bookworm AS builder

# Installer musl-tools, OpenSSL dev et pkg-config pour la compilation statique
RUN apt-get update && apt-get install -y \
    musl-tools \
    pkg-config \
    libssl-dev \
    cmake \
    && rm -rf /var/lib/apt/lists/*

# Ajouter la cible musl pour rustc
RUN rustup target add x86_64-unknown-linux-musl

WORKDIR /usr/src/app

# Copier les fichiers Cargo.toml et Cargo.lock
COPY Cargo.toml Cargo.lock ./

# Fichiers temporaires pour cacher les dépendances
RUN mkdir -p src/bin && \
    echo "" > src/lib.rs && \
    echo "fn main() {}" > src/main.rs

# Créer le dossier .cargo et le fichier config.toml avec les optimisations musl
RUN mkdir -p .cargo && \
    echo '[target.x86_64-unknown-linux-musl]' > .cargo/config.toml && \
    echo 'linker = "musl-gcc"' >> .cargo/config.toml && \
    echo '[profile.release]' >> .cargo/config.toml && \
    echo 'lto = "fat"' >> .cargo/config.toml && \
    echo 'codegen-units = 1' >> .cargo/config.toml && \
    echo 'opt-level = "z"' >> .cargo/config.toml && \
    echo 'panic = "abort"' >> .cargo/config.toml

# Build initial des dépendances avec target musl
RUN cargo build --release --target x86_64-unknown-linux-musl --features openssl/vendored

# Supprimer les fichiers temporaires
RUN rm -f src/lib.rs src/main.rs src/bin/*.rs

# Copier le reste des fichiers de l'application
COPY . .

# Build final optimisé
RUN cargo build --release --target x86_64-unknown-linux-musl --features openssl/vendored

# Strip du binaire pour réduire la taille
RUN strip target/x86_64-unknown-linux-musl/release/ironcrypt

# Étape 2 : Image finale Alpine minimale
FROM alpine:latest

# Installer runtime OpenSSL minimal pour le binaire
RUN apk add --no-cache openssl

WORKDIR /usr/src/app

# Copier le binaire statique depuis le builder
COPY --from=builder /usr/src/app/target/x86_64-unknown-linux-musl/release/ironcrypt /usr/local/bin/ironcrypt

# Définir le point d'entrée
CMD ["ironcrypt"]
