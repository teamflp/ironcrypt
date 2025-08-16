#!/bin/sh
set -e

envsubst < /etc/loki/local-config.yml.template > /etc/loki/local-config.yml

# Start Loki as a daemon
exec /usr/bin/loki --config.file=/etc/loki/local-config.yml
