#!/bin/bash
# docker-entrypoint.sh

# Fail if required vars missing
: "${MPP_ACCESS_KEY:?Missing MPP_ACCESS_KEY}"
: "${MPP_NATS_URL:?Missing MPP_NATS_URL}"
: "${MPP_NATS_USER:?Missing MPP_NATS_USER}"
: "${MPP_NATS_PASSWORD:?Missing MPP_NATS_PASSWORD}"

cat > /config/config.yml <<EOF
access_key: "${MPP_ACCESS_KEY}"
nats:
  url: "${MPP_NATS_URL}"
  authentication:
    user: "${MPP_NATS_USER}"
    password: "${MPP_NATS_PASSWORD}"
  server_ca: ${MPP_NATS_SERVER_CA:-/config/certs/ca.crt}
EOF

exec "$@"