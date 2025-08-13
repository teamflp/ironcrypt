# 🛠 Étape 1 : Construction
FROM rust:1.81.0 AS builder
# ❗ Si tu veux être strictement cohérent, tu peux aussi faire :
# FROM rust:1.81.0-bookworm AS builder

# Installer les dépendances nécessaires pour la compilation
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/app

# Copier les fichiers Cargo
COPY Cargo.toml Cargo.lock ./

# Préparer des sources minimales pour compiler les dépendances
RUN mkdir -p src \
 && echo "fn main() {}" > src/main.rs \
 && echo "pub fn lib() {}" > src/lib.rs \
 && cargo build --release \
 && rm -rf src/

# Copier le reste du projet
COPY . .

# Compiler le binaire final
RUN cargo build --release --bin ironcrypt

# 🧱 Étape 2 : Image finale
# ⚠ Changement : utiliser la même base (bookworm-slim) qu’à l’étape build
FROM debian:bookworm-slim

# Installer les bibliothèques nécessaires à l'exécution
RUN apt-get update && apt-get install -y \
    libssl-dev \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/app

# Copier le binaire depuis l'étape de build
COPY --from=builder /usr/src/app/target/release/ironcrypt /usr/local/bin/ironcrypt

EXPOSE 9000

# Point d’entrée par défaut (affiche l’aide)
CMD ["ironcrypt", "--help"]
