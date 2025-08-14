#!/bin/sh
set -e

# Generate the config file

envsubst '${GRAFANA_API_TOKEN} ${SSL_CERT_PATH} ${SSL_KEY_PATH}' \
  < /etc/nginx/nginx.conf.template > /etc/nginx/nginx.conf

# Start nginx as a daemon
exec nginx -g 'daemon off;'
