package operator

import (
	"context"
	"strings"

	"github.com/emm035/vault-secrets-engine-nats/internal/nkutil"
	"github.com/hashicorp/go-hclog"
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
	}
}

type Service struct {
	Log hclog.Logger
}

func (os *Service) InitOperator(ctx context.Context, req *logical.InitializationRequest) error {
	op, err := GetOperator(ctx, req.Storage)
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
	op, err := GetOperator(ctx, req.Storage)
	if err != nil {
		return nil, err
	} else if op == nil {
		op = new(Operator)
	}

	nk, err := nkutil.GetOrDefault(fd, "nkey", func() (nkeys.KeyPair, error) {
		return nkeys.FromSeed([]byte(op.Nkey))
	})
	if err != nil {
		return nil, err
	} else if pk, err := nk.Seed(); err == nil {
		op.Nkey = string(pk)
	}

	if e, err := logical.StorageEntryJSON(storagePath, op); err != nil {
		return nil, err
	} else if err := req.Storage.Put(ctx, e); err != nil {
		return nil, err
	}

	pubkey, opJwt, err := genJwt(req.MountPoint, nk)
	if err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"public_key": pubkey,
			"jwt":        opJwt,
		},
	}, nil
}

func (cs *Service) Read(ctx context.Context, req *logical.Request, fd *framework.FieldData) (*logical.Response, error) {
	op, err := GetOperator(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	pubkey, opJwt, err := genFromSeed(req.MountPoint, op.Nkey)
	if err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"public_key": pubkey,
			"jwt":        opJwt,
		},
	}, nil
}

func genFromSeed(mount, seed string) (pubkey, opJwt string, err error) {
	opNkey, err := nkeys.FromSeed([]byte(seed))
	if err != nil {
		return "", "", err
	}

	return genJwt(mount, opNkey)
}

func genJwt(mount string, nkey nkeys.KeyPair) (pubkey, opJwt string, err error) {
	pubkey, err = nkey.PublicKey()
	if err != nil {
		return "", "", err
	}

	claims := new(jwt.OperatorClaims)
	claims.Subject = pubkey
	claims.Name = strings.TrimRight(mount, "/")

	opJwt, err = claims.Encode(nkey)
	return
}
