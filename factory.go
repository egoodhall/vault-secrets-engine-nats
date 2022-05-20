package natsengine

import (
	"context"

	"github.com/hashicorp/vault/sdk/logical"
)

func Factory(ctx context.Context, cfg *logical.BackendConfig) (logical.Backend, error) {
	b, err := NewBackend()
	if err != nil {
		return nil, err
	}
	if err := b.Setup(ctx, cfg); err != nil {
		return nil, err
	}
	return b, nil
}
