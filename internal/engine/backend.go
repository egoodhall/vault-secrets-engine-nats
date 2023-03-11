package engine

import (
	"strings"

	"github.com/emm035/vault-secrets-engine-nats/internal/account"
	"github.com/emm035/vault-secrets-engine-nats/internal/operator"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const backendHelp = `
The NATS secrets backend dynamically generates NKeys and JWTs.
After mounting this backend, credentials to manage NATS credentials
must be configured with the "config/" endpoints.
`

func NewNatsEngine(opsvc *operator.Service, arsvc *account.UserCredsService, paths []*framework.Path, secrets []*framework.Secret) *framework.Backend {
	return &framework.Backend{
		BackendType:    logical.TypeLogical,
		Help:           strings.TrimSpace(backendHelp),
		InitializeFunc: opsvc.InitOperator,
		PeriodicFunc:   arsvc.CompactRevocations,
		Secrets:        secrets,
		Paths:          paths,
		PathsSpecial: &logical.Paths{
			LocalStorage: make([]string, 0),
			SealWrapStorage: []string{
				"operator/*",
				"account/*",
			},
		},
	}
}
