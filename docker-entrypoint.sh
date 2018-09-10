#!/bin/bash
set -e

export HOST=""
export RPC_HOST="$(uname -n)"

if [[ "$1" = "electrumx_server" ]]; then
    exec gosu bitcoin "$@"
elif [[ "$1" == "electrumx_rpc" ]]; then
    exec gosu bitcoin "$@"
else
    exec "$@"
fi
