package account

import (
	"context"
	"errors"
	"time"

	"github.com/egoodhall/vault-secrets-engine-nats/internal/nkutil"
	"github.com/egoodhall/vault-secrets-engine-nats/internal/operator"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
)

type Paths []*framework.Path

func NewPaths(svc *Service) Paths {
	return []*framework.Path{
		{
			Pattern: "accounts/" + framework.GenericNameRegex("name"),
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeString,
					Description: "The account name",
					Required:    true,
				},
				"nkey": {
					Type:        framework.TypeString,
					Description: "The NKey that will be used as the root of the trust chain",
					Required:    false,
				},
				"default_ttl": {
					Type:        framework.TypeDurationSecond,
					Description: "The default TTL of user credentials for this account",
					Default:     "15m",
					Required:    false,
				},
				"max_ttl": {
					Type:        framework.TypeDurationSecond,
					Description: "The maximum TTL of user credentials for this account",
					Default:     "1h",
					Required:    false,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{Callback: svc.Write},
				logical.UpdateOperation: &framework.PathOperation{Callback: svc.Write},
				logical.ReadOperation:   &framework.PathOperation{Callback: svc.Read},
				logical.DeleteOperation: &framework.PathOperation{Callback: svc.Delete},
			},
		},
		{
			Pattern: "accounts/" + framework.GenericNameRegex("account_name") + "/user-creds",
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
				"ttl": {
					Type:        framework.TypeDurationSecond,
					Description: "The TTL of the generated user credentials",
					Default:     "15m",
					Required:    false,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{Callback: svc.LeaseUserCreds},
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

	accountNkey, err := nkutil.GetOrDefault(fd, "nkey", nkeys.CreateAccount)
	if err != nil {
		return nil, err
	}

	account, err := getAccount(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	} else if account == nil {
		account = new(Account)
	}

	if account.DefaultTtl == 0 {
		account.DefaultTtl = fd.Get("default_ttl").(int)
	}

	if account.MaxTtl == 0 {
		account.MaxTtl = fd.Get("max_ttl").(int)
	}

	if accountSeed, err := accountNkey.Seed(); err != nil {
		return nil, err
	} else {
		account.Nkey = string(accountSeed)
	}

	if entry, err := logical.StorageEntryJSON(storagePath(name), account); err != nil {
		return nil, err
	} else if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	pubKey, err := accountNkey.PublicKey()
	if err != nil {
		return nil, err
	}

	claims := new(jwt.AccountClaims)
	claims.Subject = pubKey
	claims.Name = name
	claims.Revocations = account.Revocations

	operator, err := operator.GetOperator(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	operatorNkey, err := nkeys.FromSeed([]byte(operator.Nkey))
	if err != nil {
		return nil, err
	}

	accountJwt, err := claims.Encode(operatorNkey)
	if err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"name":       name,
			"public_key": pubKey,
			"jwt":        accountJwt,
		},
	}, nil
}

func (svc *Service) Delete(ctx context.Context, req *logical.Request, fd *framework.FieldData) (*logical.Response, error) {
	name := fd.Get("name").(string)
	if name == "" {
		return nil, errors.New("account cannot be empty name")
	}

	if err := req.Storage.Delete(ctx, storagePath(name)); err != nil {
		return nil, err
	}

	return nil, nil
}

func (svc *Service) Read(ctx context.Context, req *logical.Request, fd *framework.FieldData) (*logical.Response, error) {
	name := fd.Get("name").(string)
	if name == "" {
		return nil, errors.New("account cannot be empty name")
	}

	account, err := getAccount(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}

	accountNkey, err := nkeys.FromSeed([]byte(account.Nkey))
	if err != nil {
		return nil, err
	}

	pubKey, err := accountNkey.PublicKey()
	if err != nil {
		return nil, err
	}

	claims := new(jwt.AccountClaims)
	claims.Subject = pubKey
	claims.Name = name
	claims.Revocations = account.Revocations

	operator, err := operator.GetOperator(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	operatorNkey, err := nkeys.FromSeed([]byte(operator.Nkey))
	if err != nil {
		return nil, err
	}

	accountJwt, err := claims.Encode(operatorNkey)
	if err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"account_name": name,
			"public_key":   pubKey,
			"jwt":          accountJwt,
		},
	}, nil
}

func (svc *Service) LeaseUserCreds(ctx context.Context, req *logical.Request, fd *framework.FieldData) (*logical.Response, error) {
	accountName := fd.Get("account_name").(string)
	if accountName == "" {
		return nil, errors.New("account name cannot be empty")
	}

	account, err := getAccount(ctx, req.Storage, accountName)
	if err != nil {
		return nil, err
	}

	userNkey, err := nkutil.GetOrDefault(fd, "nkey", nkeys.CreateUser)
	if err != nil {
		return nil, err
	}

	pubKey, err := userNkey.PublicKey()
	if err != nil {
		return nil, err
	}

	ttl := account.DefaultTtl
	if t := fd.Get("ttl").(int); t != 0 && t < account.MaxTtl {
		ttl = t
	}

	claims := new(jwt.UserClaims)
	claims.Subject = pubKey
	claims.Expires = time.Now().Add(time.Duration(ttl) * time.Second).Unix()

	if name := fd.Get("name").(string); name != "" {
		claims.Name = name
	}

	accountNkey, err := nkeys.FromSeed([]byte(account.Nkey))
	if err != nil {
		return nil, err
	}

	userJwt, err := claims.Encode(accountNkey)
	if err != nil {
		return nil, err
	}

	userSeed, err := userNkey.Seed()
	if err != nil {
		return nil, err
	}

	accountSeed, err := accountNkey.Seed()
	if err != nil {
		return nil, err
	}

	res := svc.Secret.Response(
		map[string]interface{}{
			"account_name": accountName,
			"nkey":         string(userSeed),
			"jwt":          userJwt,
		},
		map[string]interface{}{
			"account_name": accountName,
			"account_nkey": string(accountSeed),
			"user_name":    claims.Name,
			"user_nkey":    string(userSeed),
		},
	)

	return res, nil
}

type UserCredsService struct {
	Logger hclog.Logger
}

// Generates a new JWT with the
func (ucSvc *UserCredsService) RenewUserCreds(ctx context.Context, req *logical.Request, fd *framework.FieldData) (*logical.Response, error) {
	account, err := getAccount(ctx, req.Storage, req.Secret.InternalData["account_name"].(string))
	if err != nil {
		return nil, err
	}

	accountNkey, err := nkeys.FromSeed([]byte(req.Secret.InternalData["account_nkey"].(string)))
	if err != nil {
		return nil, err
	}

	userNkey, err := nkeys.FromSeed([]byte(req.Secret.InternalData["user_nkey"].(string)))
	if err != nil {
		return nil, err
	}

	pubKey, err := userNkey.PublicKey()
	if err != nil {
		return nil, err
	}

	ttl := req.Secret.Increment
	if ttl == 0 {
		ttl = time.Duration(account.DefaultTtl) * time.Second
	} else if ttl > (time.Duration(account.MaxTtl) * time.Second) {
		ttl = time.Duration(account.MaxTtl) * time.Second
	}

	ucSvc.Logger.Error("", "ttl", ttl, "default_ttl", time.Duration(account.DefaultTtl)*time.Second, "max_ttl", time.Duration(account.MaxTtl)*time.Second)

	claims := new(jwt.UserClaims)
	claims.Subject = pubKey
	claims.Expires = time.Now().Add(ttl).Unix()

	if name := req.Secret.InternalData["user_name"].(string); name != "" {
		claims.Name = name
	}

	userJwt, err := claims.Encode(accountNkey)
	if err != nil {
		return nil, err
	}

	userSeed, err := userNkey.Seed()
	if err != nil {
		userSeed = make([]byte, 0)
	}

	res := &logical.Response{
		Secret: req.Secret,
		Data: map[string]interface{}{
			"nkey": string(userSeed),
			"jwt":  userJwt,
		},
	}

	res.Secret.TTL = ttl
	res.Secret.LeaseOptions = logical.LeaseOptions{
		TTL:       ttl,
		Renewable: true,
	}

	return res, nil
}

// Revoke the specified user credentials. This will add the user's public key
// to the account JWT's revocation map
func (ucSvc *UserCredsService) RevokeUserCreds(ctx context.Context, req *logical.Request, fd *framework.FieldData) (*logical.Response, error) {
	accountName := req.Secret.InternalData["account_name"].(string)
	account, err := getAccount(ctx, req.Storage, accountName)
	if err != nil {
		return nil, err
	}

	userNkey, err := nkeys.FromSeed([]byte(req.Secret.InternalData["user_nkey"].(string)))
	if err != nil {
		return nil, err
	}
	pubKey, err := userNkey.PublicKey()
	if err != nil {
		return nil, err
	}

	if account.Revocations == nil {
		account.Revocations = jwt.RevocationList{}
	}
	account.Revocations.Revoke(pubKey, time.Now())

	if e, err := logical.StorageEntryJSON(storagePath(accountName), account); err != nil {
		return nil, err
	} else if err := req.Storage.Put(ctx, e); err != nil {
		return nil, err
	}

	return nil, nil
}

// CompactRevocations will revoke all JWTs created for the account in the last hour period. If any
// tokens were manually revoked already, they will be compacted to reduce the account JWT's size.
func (ucSvc *UserCredsService) CompactRevocations(ctx context.Context, req *logical.Request) error {
	accountNames, err := req.Storage.List(ctx, "accounts/")
	if err != nil {
		return err
	}

	for _, accountName := range accountNames {
		account, err := getAccount(ctx, req.Storage, accountName)
		if err != nil {
			return err
		}

		if account.Revocations == nil {
			account.Revocations = jwt.RevocationList{}
		}

		// Any JWTs > 1 hr old will have expired
		account.Revocations.Revoke(jwt.All, time.Now().Add(-1*time.Hour))
		account.Revocations.MaybeCompact()

		if entry, err := logical.StorageEntryJSON(storagePath(accountName), account); err != nil {
			return err
		} else if err := req.Storage.Put(ctx, entry); err != nil {
			return err
		}
	}

	return nil
}
