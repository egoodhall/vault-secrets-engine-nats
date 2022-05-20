package operator

import (
	"context"
	"strings"

	"github.com/emm035/nats-secrets-engine/internal/nkutil"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
)

type Paths []*framework.Path

func NewPaths(os *Service) Paths {
	return []*framework.Path{
		{
			Pattern: "operator",
			Fields: map[string]*framework.FieldSchema{
				"nkey": {
					Type:        framework.TypeString,
					Description: "The NKey that will be used as the root of the trust chain",
					Required:    false,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{Callback: os.Write},
				logical.UpdateOperation: &framework.PathOperation{Callback: os.Write},
				logical.ReadOperation:   &framework.PathOperation{Callback: os.Read},
			},
		},
		{
			Pattern: "operator/jwt",
			Fields: map[string]*framework.FieldSchema{
				"account_server_url": {
					Type:        framework.TypeString,
					Description: "The NKey that will be used as the root account",
					Required:    false,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{Callback: os.ReadJwt},
			},
		},
	}
}

type Service struct {
}

func (os *Service) InitOperator(ctx context.Context, req *logical.InitializationRequest) error {
	op, err := getOperator(ctx, req.Storage)
	if err != nil {
		return err
	} else if op == nil {
		op = new(Operator)
	}

	if op.Nkey != "" {
	} else if kp, err := nkeys.CreateOperator(); err != nil {
		return err
	} else if seed, err := kp.Seed(); err != nil {
	} else {
		op.Nkey = string(seed)
	}

	if e, err := logical.StorageEntryJSON(storagePath, op); err != nil {
		return err
	} else if err := req.Storage.Put(ctx, e); err != nil {
		return err
	}

	return nil
}

func (os *Service) Write(ctx context.Context, req *logical.Request, fd *framework.FieldData) (*logical.Response, error) {
	op, err := getOperator(ctx, req.Storage)
	if err != nil {
		return nil, err
	} else if op == nil {
		op = new(Operator)
	}

	opNkey, err := nkutil.GetOrDefault(fd, "nkey", nkeys.CreateOperator)
	if err != nil {
		return nil, err
	}

	// Get public key
	pubKey, err := opNkey.PublicKey()
	if err != nil {
		return nil, err
	}

	if e, err := logical.StorageEntryJSON(storagePath, op); err != nil {
		return nil, err
	} else if err := req.Storage.Put(ctx, e); err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"public_key": pubKey,
		},
	}, nil
}

func (cs *Service) Read(ctx context.Context, req *logical.Request, fd *framework.FieldData) (*logical.Response, error) {
	op, err := getOperator(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	opNkey, err := nkeys.FromSeed([]byte(op.Nkey))
	if err != nil {
		return nil, err
	}

	pubKey, err := opNkey.PublicKey()
	if err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"public_key": pubKey,
		},
	}, nil
}

func (cs *Service) ReadJwt(ctx context.Context, req *logical.Request, fd *framework.FieldData) (*logical.Response, error) {
	op, err := getOperator(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	opNkey, err := nkeys.FromSeed([]byte(op.Nkey))
	if err != nil {
		return nil, err
	}

	pubKey, err := opNkey.PublicKey()
	if err != nil {
		return nil, err
	}

	claims := new(jwt.OperatorClaims)
	claims.Subject = pubKey
	claims.Name = strings.TrimRight(req.MountPoint, "/")

	opJwt, err := claims.Encode(opNkey)
	if err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"public_key": pubKey,
			"jwt":        opJwt,
		},
	}, nil
}
