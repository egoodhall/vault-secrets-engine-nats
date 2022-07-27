# Vault secrets engine for NATS

```bash
# Enable the NATS secrets engine
vault secrets enable nats

# An operator will be created by default.
# The operator's NKey seed can be overridden
vault write nats/operator nkey=$(nk -gen operator)

# Get the operator's public key and a JWT signed
# by the private key. This can be used as the root
# JWT for a NATS cluster
vault read nats/operator

# Create / update a NATS account. The JWT for the
# account will be signed using the corresponding
# mount's operator private key.
vault write nats/accounts/SYS nkey=$(nk -gen account)

# Get an account's JWT and public key. This can be used
# to back an account JWT service
vault read nats/accounts/SYS

# Generate user credentials for the specified account. The credentials
# will expire after 15m (overridable using the ttl and max_ttl fields)
# and follow the normal semantics for vault secret leases.
vault read nats/accounts/SYS/user-creds
```
