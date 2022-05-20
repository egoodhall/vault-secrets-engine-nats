package account

import (
	"context"
	"errors"
	"time"

	"github.com/emm035/vault-plugin-secrets-nats/internal/nkutil"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
)

type Paths []*framework.Path

func NewPaths(s *Service) Paths {
	return []*framework.Path{
		{
			Pattern: "account/" + framework.GenericNameRegex("name"),
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeString,
					Description: "The account name",
					Default:     "",
					Required:    false,
				},
				"nkey": {
					Type:        framework.TypeString,
					Description: "The NKey that will be used as the root of the trust chain",
					Required:    false,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{Callback: s.Write},
				logical.UpdateOperation: &framework.PathOperation{Callback: s.Write},
				logical.ReadOperation:   &framework.PathOperation{Callback: s.Read},
			},
		},
		{
			Pattern: "account/" + framework.GenericNameRegex("name") + "/jwt",
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeString,
					Description: "The account name",
					Default:     "",
					Required:    false,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{Callback: s.ReadJwt},
			},
		},
		{
			Pattern: "account/" + framework.GenericNameRegex("account_name") + "/user-creds",
			Fields: map[string]*framework.FieldSchema{
				"account_name": {
					Type:        framework.TypeString,
					Description: "The account name",
					Default:     "",
					Required:    false,
				},
				"name": {
					Type:        framework.TypeString,
					Description: "The user name",
					Default:     "",
					Required:    false,
				},
				"nkey": {
					Type:        framework.TypeString,
					Description: "The user NKey",
					Default:     "",
					Required:    false,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{Callback: s.LeaseUserCreds},
			},
		},
	}
}

type Service struct {
	Secret UserCredentialsSecret
	Logger hclog.Logger
}

func (svc *Service) Write(ctx context.Context, req *logical.Request, fd *framework.FieldData) (*logical.Response, error) {
	name := fd.Get("name").(string)
	if name == "" {
		return nil, errors.New("account cannot be empty name")
	}

	actNkey, err := nkutil.GetOrDefault(fd, "nkey", nkeys.CreateAccount)
	if err != nil {
		return nil, err
	}

	act, err := getAccount(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	} else if act == nil {
		act = new(Account)
	}

	if actSeed, err := actNkey.Seed(); err != nil {
		return nil, err
	} else {
		act.Nkey = string(actSeed)
	}

	if e, err := logical.StorageEntryJSON(storagePath(name), act); err != nil {
		return nil, err
	} else if err := req.Storage.Put(ctx, e); err != nil {
		return nil, err
	}

	pubKey, err := actNkey.PublicKey()
	if err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"public_key": pubKey,
		},
	}, nil
}

func (svc *Service) Read(ctx context.Context, req *logical.Request, fd *framework.FieldData) (*logical.Response, error) {
	name := fd.Get("name").(string)
	if name == "" {
		return nil, errors.New("account cannot be empty name")
	}

	act, err := getAccount(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}

	actNkey, err := nkeys.FromSeed([]byte(act.Nkey))
	if err != nil {
		return nil, err
	}

	pubKey, err := actNkey.PublicKey()
	if err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"public_key": pubKey,
		},
	}, nil
}

func (svc *Service) ReadJwt(ctx context.Context, req *logical.Request, fd *framework.FieldData) (*logical.Response, error) {
	name := fd.Get("name").(string)
	if name == "" {
		return nil, errors.New("account cannot be empty name")
	}

	act, err := getAccount(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}

	actNkey, err := nkeys.FromSeed([]byte(act.Nkey))
	if err != nil {
		return nil, err
	}

	pubKey, err := actNkey.PublicKey()
	if err != nil {
		return nil, err
	}

	claims := new(jwt.AccountClaims)
	claims.Subject = pubKey
	claims.Name = name
	claims.Revocations = act.Revocations

	opJwt, err := claims.Encode(actNkey)
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

func (svc *Service) LeaseUserCreds(ctx context.Context, req *logical.Request, fd *framework.FieldData) (*logical.Response, error) {
	actName := fd.Get("account_name").(string)
	if actName == "" {
		return nil, errors.New("account name cannot be empty")
	}

	act, err := getAccount(ctx, req.Storage, actName)
	if err != nil {
		return nil, err
	}

	usrNkey, err := nkutil.GetOrDefault(fd, "nkey", nkeys.CreateUser)
	if err != nil {
		return nil, err
	}

	pubKey, err := usrNkey.PublicKey()
	if err != nil {
		return nil, err
	}

	claims := new(jwt.UserClaims)
	claims.Subject = pubKey
	claims.Expires = time.Now().Add(15 * time.Minute).Unix()

	if name := fd.Get("name").(string); name != "" {
		claims.Name = name
	}

	actNkey, err := nkeys.FromSeed([]byte(act.Nkey))
	if err != nil {
		return nil, err
	}

	usrJwt, err := claims.Encode(actNkey)
	if err != nil {
		return nil, err
	}

	usrSeed, err := usrNkey.Seed()
	if err != nil {
		return nil, err
	}

	actSeed, err := actNkey.Seed()
	if err != nil {
		return nil, err
	}

	return svc.Secret.Response(
		map[string]interface{}{
			"nkey": string(usrSeed),
			"jwt":  usrJwt,
		},
		map[string]interface{}{
			"account_name": actName,
			"account_nkey": string(actSeed),
			"user_name":    claims.Name,
			"user_nkey":    string(usrSeed),
		},
	), nil
}

type RenewalService struct {
	Logger hclog.Logger
}

func (rsvc *RenewalService) RenewUserCreds(ctx context.Context, req *logical.Request, fd *framework.FieldData) (*logical.Response, error) {
	actNkey, err := nkeys.FromSeed([]byte(req.Secret.InternalData["account_nkey"].(string)))
	if err != nil {
		return nil, err
	}

	usrNkey, err := nkeys.FromSeed([]byte(req.Secret.InternalData["user_nkey"].(string)))
	if err != nil {
		return nil, err
	}

	pubKey, err := usrNkey.PublicKey()
	if err != nil {
		return nil, err
	}

	claims := new(jwt.UserClaims)
	claims.Subject = pubKey
	claims.Expires = time.Now().Add(15 * time.Minute).Unix()

	if name := req.Secret.InternalData["user_name"].(string); name != "" {
		claims.Name = name
	}

	usrJwt, err := claims.Encode(actNkey)
	if err != nil {
		return nil, err
	}

	seed, err := usrNkey.Seed()
	if err != nil {
		seed = make([]byte, 0)
	}

	return &logical.Response{
		Secret: req.Secret,
		Data: map[string]interface{}{
			"nkey": string(seed),
			"jwt":  usrJwt,
		},
	}, nil
}

func (rsvc *RenewalService) RevokeUserCreds(ctx context.Context, req *logical.Request, fd *framework.FieldData) (*logical.Response, error) {
	accountName := req.Secret.InternalData["account_name"].(string)
	act, err := getAccount(ctx, req.Storage, accountName)
	if err != nil {
		return nil, err
	}

	usrNkey, err := nkeys.FromSeed([]byte(req.Secret.InternalData["user_nkey"].(string)))
	if err != nil {
		return nil, err
	}
	pubKey, err := usrNkey.PublicKey()
	if err != nil {
		return nil, err
	}

	if act.Revocations == nil {
		act.Revocations = jwt.RevocationList{}
	}
	act.Revocations.Revoke(pubKey, time.Now())

	if e, err := logical.StorageEntryJSON(storagePath(accountName), act); err != nil {
		return nil, err
	} else if err := req.Storage.Put(ctx, e); err != nil {
		return nil, err
	}

	return nil, nil
}

// CompactRevocations will revoke all JWTs created for the account in the last hour period. If any
// tokens were manually revoked already, they will be compacted to reduce the account JWT's size.
func (rsvc *RenewalService) CompactRevocations(ctx context.Context, req *logical.Request) error {
	actNames, err := req.Storage.List(ctx, "account/")
	if err != nil {
		return err
	}

	for _, actName := range actNames {
		act, err := getAccount(ctx, req.Storage, actName)
		if err != nil {
			return err
		}

		if act.Revocations == nil {
			act.Revocations = jwt.RevocationList{}
		}
		act.Revocations.Revoke(jwt.All, time.Now().Add(-15*time.Minute))
		act.Revocations.MaybeCompact()

		if e, err := logical.StorageEntryJSON(storagePath(actName), act); err != nil {
			return err
		} else if err := req.Storage.Put(ctx, e); err != nil {
			return err
		}
	}

	return nil
}
