//go:build wireinject

package engine

import (
	"github.com/emm035/vault-secrets-engine-nats/internal/account"
	"github.com/emm035/vault-secrets-engine-nats/internal/operator"
	"github.com/google/wire"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func NewPaths(operator operator.Paths, account account.Paths) []*framework.Path {
	return framework.PathAppend(operator, account)
}

func NewSecrets(ucrds account.UserCredentialsSecret) []*framework.Secret {
	return []*framework.Secret{
		ucrds.Secret,
	}
}

func NewBackend() (logical.Backend, error) {
	panic(wire.Build(
		NewLogger,
		NewNatsEngine,
		account.ProviderSet,
		operator.ProviderSet,
		NewPaths,
		NewSecrets,
		wire.Bind(new(logical.Backend), new(*framework.Backend)),
	))
}
