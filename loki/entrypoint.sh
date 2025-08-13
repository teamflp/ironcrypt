#!/bin/sh
set -e

envsubst < /etc/loki/local-config.yml.template > /etc/loki/local-config.yml

exec /usr/bin/loki -config.file=/etc/loki/local-config.yml
