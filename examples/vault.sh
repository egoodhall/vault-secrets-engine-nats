#!/usr/bin/env bash

dir="$(dirname $(realpath $0))"
root="$(dirname $dir)"
bin="$root/bin"

cleanup() {
  kill -INT $pid 2>&1 > /dev/null && {
    echo "Sent SIGINT to vault ($pid)"
    wait 2>&1 > /dev/null
  } || {
    echo "No vault binary running"
  }
}

set -e
trap cleanup EXIT

# Generate root token to use
token=$(uuidgen | tr '[:upper:]' '[:lower:]')

# Generate config file for vault
config="
plugin_directory = \"$bin\"
log_level = \"err\"

api_addr = \"http://127.0.0.1:8200\"
"

# Start vault
vault server -dev -config <(echo $config) -dev-root-token-id=$token &
pid=$!

# Give vault a second to start
sleep 1

# Build plugin
go build -v -ldflags="-s -w" -o "$bin/nats" "$root/cmd/nats-secrets-engine"

# Set up environment
export VAULT_TOKEN=$token
export VAULT_ADDR=http://localhost:8200

# Register and enable plugin
vault plugin register -sha256="$(sha256sum "$bin/nats" | cut -d ' ' -f1)" secret nats
vault secrets enable nats

vault write -force nats/accounts/SYS 2>&1 > /dev/null

echo -e "\033[0;34m
This shell is configured for the vault example server:

export VAULT_TOKEN=$token
export VAULT_ADDR=http://localhost:8200

A NATS operator and service account have been configured,
and can be accessed using the following commands:

$ vault read nats/operator
$ vault read nats/accounts/SYS

\033[0;33muse ctrl+D to close this shell and shut down vault
\033[0m"

set +e

# Open a shell with the vault token set
PS1="\033[0;31mvault-nats-example\033[0m $ " bash

