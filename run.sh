#!/bin/bash

# Exit immediately if a command exits with a non-zero status.
set -e

# Default to .env if no environment file is specified as the first argument.
ENV_FILE=${1:-.env}

# Check if the environment file exists to provide a clear error message.
if [ ! -f "$ENV_FILE" ]; then
    echo "❌ Error: Environment file '$ENV_FILE' not found."
    exit 1
fi

echo "🚀 Starting services using environment file: $ENV_FILE"

docker compose --env-file "$ENV_FILE" up --build