package account

import (
	"time"

	"github.com/hashicorp/vault/sdk/framework"
)

type UserCredentialsSecret struct {
	*framework.Secret
}

func NewUserCredentialsSecret(ucs *UserCredsService) UserCredentialsSecret {
	return UserCredentialsSecret{
		&framework.Secret{
			Type:            "nats_credentials",
			DefaultDuration: 15 * time.Minute,
			Renew:           ucs.RenewUserCreds,
			Revoke:          ucs.RevokeUserCreds,
			Fields: map[string]*framework.FieldSchema{
				"nkey": {
					Type:        framework.TypeString,
					Description: "The NKey identifying the user",
				},
				"jwt": {
					Type:        framework.TypeString,
					Description: "The JWT describing the permissions granted to the user",
				},
			},
		},
	}
}
