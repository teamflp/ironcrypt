#!/bin/sh
set -e

# Generate the config file@'
envsubst < /etc/alertmanager/config.yml.template > /etc/alertmanager/config.yml

exec /bin/alertmanager --config.file=/etc/alertmanager/config.yml
