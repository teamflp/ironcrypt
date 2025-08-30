# Makefile for IronCrypt Docker management

# --- Variables ---
# Default environment file for development
ENV_FILE ?=.env
# Production environment file
PROD_ENV_FILE ?=.env.prod
# Use Docker Compose V2 syntax, which is now standard.
COMPOSE = sudo docker compose

.PHONY: help all build dev prod stop logs clean test coverage

# --- Main Targets ---

# Help target
help:
	@echo "Makefile targets:"
	@echo "  make, all      -> dev (default)"
	@echo "  build          Build Docker images"
	@echo "  dev            Start services in development mode (foreground)"
	@echo "  prod           Start services in production mode (foreground)"
	@echo "  stop           Stop containers (docker compose down)"
	@echo "  logs           Tail logs (docker compose logs -f)"
	@echo "  clean          Remove containers, volumes, orphans and prune system"
	@echo "  test           Run tests inside the ironcrypt service"
	@echo "  coverage       Run tarpaulin coverage inside the ironcrypt service"
	@echo ""
	@echo "Usage: make <target>  e.g., 'make dev' or 'make prod'"

# Default target when running 'make'
all: dev

# Build the Docker images without starting the containers
build:
	@echo "🏗️  Building Docker images..."
	$(COMPOSE) build

# Start services in development mode (runs in foreground)
dev:
	@echo "🚀  Starting services in DEVELOPMENT mode (Ctrl+C to stop)..."
	$(COMPOSE) --env-file $(ENV_FILE) up --build

# Start services in production mode (runs in foreground)
prod:
	@echo "🚀  Starting services in PRODUCTION mode (Ctrl+C to stop)..."
	$(COMPOSE) --env-file $(PROD_ENV_FILE) up --build

# --- Utility Targets ---

# Stop the running containers
stop:
	@echo "🛑  Stopping containers..."
	$(COMPOSE) down

# Follow the logs of running services (if they are detached)
logs:
	@echo "📜  Tailing logs..."
	$(COMPOSE) logs -f

# Clean up everything: stop containers, remove volumes, and prune the system
# WARNING: This is a destructive operation.
clean:
	@echo "🧹  Cleaning up Docker environment..."
	$(COMPOSE) down -v --remove-orphans
	@echo "🧹  Pruning unused Docker system resources..."
	docker system prune -f

test:
	@echo "🧪  Tests unitaires..."
	$(COMPOSE) --env-file $(ENV_FILE) run --rm tests cargo test

coverage:
	@echo "📊 Couverture de test..."
	$(COMPOSE) --env-file $(ENV_FILE) run --rm ironcryptd cargo tarpaulin --out Html