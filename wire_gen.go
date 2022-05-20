// Code generated by Wire. DO NOT EDIT.

//go:generate go run github.com/google/wire/cmd/wire
//go:build !wireinject
// +build !wireinject

package natsengine

import (
	"github.com/emm035/vault-plugin-secrets-nats/internal"
	"github.com/emm035/vault-plugin-secrets-nats/internal/account"
	"github.com/emm035/vault-plugin-secrets-nats/internal/operator"
	"github.com/hashicorp/vault/sdk/logical"
)

// Injectors from wire.go:

func NewBackend() (logical.Backend, error) {
	service := &operator.Service{}
	logger := NewLogger()
	renewalService := &account.RenewalService{
		Logger: logger,
	}
	paths := operator.NewPaths(service)
	userCredentialsSecret := account.NewUserCredentialsSecret(renewalService)
	accountService := &account.Service{
		Secret: userCredentialsSecret,
		Logger: logger,
	}
	accountPaths := account.NewPaths(accountService)
	v := internal.NewPaths(paths, accountPaths)
	v2 := internal.NewSecrets(userCredentialsSecret)
	frameworkBackend := NewNatsEngine(service, renewalService, v, v2)
	return frameworkBackend, nil
}
