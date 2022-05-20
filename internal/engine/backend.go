package engine

import (
	"strings"

	"github.com/emm035/nats-secrets-engine/internal/account"
	"github.com/emm035/nats-secrets-engine/internal/operator"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const backendHelp = `
The NATS secrets backend dynamically generates NKeys and JWTs.
After mounting this backend, credentials to manage NATS credentials
must be configured with the "config/" endpoints.
`

type backend struct {
	*framework.Backend
}

func NewNatsEngine(opsvc *operator.Service, arsvc *account.RenewalService, paths []*framework.Path, secrets []*framework.Secret) *framework.Backend {
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
