#!/bin/bash
set -e

export RPC_HOST="$(uname -n)"

if [ -f /run/secrets/ocean_user ] && [ -f /run/secrets/ocean_pass ]; then
    export DAEMON_URL="$(cat /run/secrets/ocean_user):$(cat /run/secrets/ocean_pass)@${ELECTRUM_HOST}:${ELECTRUM_PORT}"
fi

if [ -f /run/secrets/ocean_pass ] && [ ! -f /run/secrets/ocean_user ]; then
    export DAEMON_URL="${ELECTRUM_USER}:$(cat /run/secrets/ocean_pass)@${ELECTRUM_HOST}:${ELECTRUM_PORT}"
fi

if [[ "$1" = "electrumx_server" ]]; then
    chown -R bitcoin /electrum-db
    gosu bitcoin /usr/src/cb-electrum-server/compact_history.py
    exec gosu bitcoin "$@"
elif [[ "$1" == "electrumx_rpc" ]]; then
    exec gosu bitcoin "$@"
else
    exec "$@"
fi
