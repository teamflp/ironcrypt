# Makefile for IronCrypt Docker management

# --- Variables ---
ENV_FILE ?=.env
PROD_ENV_FILE ?=.env.prod
COMPOSE = docker compose
LAB = $(COMPOSE) --profile lab -f docker-compose.yml -f docker-compose.lab.yml --env-file $(ENV_FILE)
PROD = $(COMPOSE) --profile prod -f docker-compose.yml -f docker-compose.prod.yml --env-file $(PROD_ENV_FILE)

.PHONY: help all build lab dev prod stop logs clean test coverage bootstrap-lab

help:
	@echo "Makefile targets:"
	@echo "  bootstrap-lab  Copy *.example fixtures for local lab use"
	@echo "  build          Build Docker images (lab + prod files)"
	@echo "  lab / dev      Start LAB stack (Vault -dev root token allowed)"
	@echo "  prod           Start PROD stack (no Vault root token)"
	@echo "  stop           Stop containers"
	@echo "  logs           Tail logs"
	@echo "  clean          Remove containers/volumes/orphans"
	@echo "  test           Run cargo test in the builder container"
	@echo "  coverage       Run tarpaulin in the builder container"

all: lab

bootstrap-lab:
	@echo "Copying example fixtures (will not overwrite existing files)..."
	@test -f keys.json || cp keys.json.example keys.json
	@test -f ironcrypt.toml || cp ironcrypt.toml.example ironcrypt.toml
	@mkdir -p keys
	@test -f keys/private_key_v1.pem || cp private_key_v1.pem.example keys/private_key_v1.pem
	@test -f keys/public_key_v1.pem || cp public_key_v1.pem.example keys/public_key_v1.pem
	@echo "Done. Edit keys.json / ironcrypt.toml before starting the daemon."

build:
	@echo "Building Docker images..."
	$(LAB) build
	$(PROD) build

lab dev:
	@echo "Starting LAB stack (Ctrl+C to stop)..."
	$(LAB) up --build

prod:
	@echo "Starting PROD stack (Ctrl+C to stop)..."
	$(PROD) up --build

stop:
	@echo "Stopping containers..."
	$(LAB) down --remove-orphans || true
	$(PROD) down --remove-orphans || true

logs:
	$(LAB) logs -f

clean:
	@echo "Cleaning Docker environment..."
	$(LAB) down -v --remove-orphans || true
	$(PROD) down -v --remove-orphans || true
	docker system prune -f

test:
	@echo "Unit/integration tests..."
	$(LAB) run --rm tests cargo test --features full

coverage:
	@echo "Coverage..."
	$(LAB) run --rm tests cargo tarpaulin --out Html
