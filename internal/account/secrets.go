package account

import (
	"time"

	"github.com/hashicorp/vault/sdk/framework"
)

type UserCredentialsSecret struct {
	*framework.Secret
}

func NewUserCredentialsSecret(rs *RenewalService) UserCredentialsSecret {
	return UserCredentialsSecret{
		&framework.Secret{
			Type:            "nats_credentials",
			DefaultDuration: 15 * time.Minute,
			Renew:           rs.RenewUserCreds,
			Revoke:          rs.RevokeUserCreds,
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
