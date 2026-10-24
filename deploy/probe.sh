#!/bin/sh
set -eu

case "${1:-}" in
    live) endpoint=/livez ;;
    ready) endpoint=/healthz ;;
    *) echo "usage: filtr-probe live|ready" >&2; exit 2 ;;
esac

# Keep the admin secret out of curl's process arguments.
printf 'header = "Authorization: Bearer %s"\n' "$FILTR_ADMIN_TOKEN" |
    curl --config - --fail --silent --show-error --noproxy '*' \
        --max-time 2 --output /dev/null \
        "http://${FILTR_ADMIN_LISTEN:-127.0.0.1:9090}${endpoint}"
