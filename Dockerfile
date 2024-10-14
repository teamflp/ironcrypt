# Étape 1 : Construction
FROM rust:1.81.0 AS builder

# Installer OpenSSL et pkg-config
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/app

# Copier les fichiers Cargo.toml et Cargo.lock
COPY Cargo.toml Cargo.lock ./

# Créer des fichiers temporaires pour lib.rs et les binaires
RUN mkdir -p src/bin && \
    echo "" > src/lib.rs && \
    echo "fn main() {}" > src/main.rs

# Si vous avez des binaires dans src/bin/, créez des fichiers temporaires pour eux
# Par exemple, si vous avez src/bin/ironcrypt-cli.rs
# RUN echo "fn main() {}" > src/bin/ironcrypt-cli.rs

# Compiler les dépendances
RUN cargo build --release

# Supprimer les fichiers temporaires
RUN rm -f src/lib.rs src/main.rs src/bin/*.rs

# Copier le reste des fichiers de l'application
COPY . .

# Construire l'application
RUN cargo build --release

# Étape 2 : Création de l'image finale
FROM debian:buster-slim

# Installer les bibliothèques nécessaires pour exécuter le binaire
RUN apt-get update && apt-get install -y \
    libssl1.1 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/app

# Copier le binaire depuis l'étape de construction
COPY --from=builder /usr/src/app/target/release/ironcrypt-cli /usr/local/bin/ironcrypt-cli

# Définir le point d'entrée
CMD ["ironcrypt-cli"]
