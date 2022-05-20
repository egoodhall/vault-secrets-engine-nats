package nkutil

import (
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/nats-io/nkeys"
)

func Get(fd *framework.FieldData, field string) (nkeys.KeyPair, error) {
	if nk, ok := fd.GetOk(field); !ok {
		return nil, fmt.Errorf("no field: %s", field)
	} else {
		return nkeys.FromSeed([]byte(nk.(string)))
	}
}

func GetOrDefault(fd *framework.FieldData, field string, defaultFactory func() (nkeys.KeyPair, error)) (nkeys.KeyPair, error) {
	if kp, err := Get(fd, field); err != nil {
		return defaultFactory()
	} else {
		return kp, nil
	}
}
