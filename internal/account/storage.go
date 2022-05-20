package account

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/nats-io/jwt/v2"
)

func storagePath(name string) string {
	return "account/" + name
}

type Account struct {
	Name        string             `json:"name"`
	Nkey        string             `json:"nkey"`
	Revocations jwt.RevocationList `json:"revocations,omitempty"`
}

func getAccount(ctx context.Context, s logical.Storage, name string) (*Account, error) {
	entry, err := s.Get(ctx, storagePath(name))
	if err != nil {
		return nil, err
	}

	if entry == nil {
		return nil, nil
	}

	config := new(Account)
	if err := entry.DecodeJSON(&config); err != nil {
		return nil, fmt.Errorf("error reading account: %w", err)
	}

	return config, nil
}
