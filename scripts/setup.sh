#!/usr/bin/env bash

set -e

# Install & enable plugin
make plugin
vault plugin register -sha256="$(sha256sum ./bin/nats | cut -d ' ' -f1)" secret nats
vault secrets enable nats

# List operator information
vault read nats/operator

# Configure account
vault write -force nats/accounts/SYS
