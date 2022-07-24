package operator

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/sdk/logical"
)

const storagePath = "operator"

type Operator struct {
	Nkey string `json:"nkey"`
}

func GetOperator(ctx context.Context, s logical.Storage) (*Operator, error) {
	entry, err := s.Get(ctx, storagePath)
	if err != nil {
		return nil, err
	}

	if entry == nil {
		return nil, nil
	}

	config := new(Operator)
	if err := entry.DecodeJSON(&config); err != nil {
		return nil, fmt.Errorf("error reading operator: %w", err)
	}

	return config, nil
}
