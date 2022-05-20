//go:build wireinject

package natsengine

import (
	"github.com/emm035/vault-plugin-secrets-nats/internal"
	"github.com/google/wire"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func NewBackend() (logical.Backend, error) {
	panic(wire.Build(
		NewLogger,
		NewNatsEngine,
		internal.AggregatorSet,
		wire.Bind(new(logical.Backend), new(*framework.Backend)),
	))
}
