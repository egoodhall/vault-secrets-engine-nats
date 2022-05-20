package internal

import (
	"github.com/emm035/vault-plugin-secrets-nats/internal/account"
	"github.com/emm035/vault-plugin-secrets-nats/internal/operator"
	"github.com/google/wire"
	"github.com/hashicorp/vault/sdk/framework"
)

var AggregatorSet = wire.NewSet(
	account.ProviderSet,
	operator.ProviderSet,
	NewPaths,
	NewSecrets,
)

func NewPaths(operator operator.Paths, account account.Paths) []*framework.Path {
	return framework.PathAppend(operator, account)
}

func NewSecrets(ucrds account.UserCredentialsSecret) []*framework.Secret {
	return []*framework.Secret{
		ucrds.Secret,
	}
}
