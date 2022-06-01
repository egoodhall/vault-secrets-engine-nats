// Code generated by Wire. DO NOT EDIT.

//go:generate go run github.com/google/wire/cmd/wire
//go:build !wireinject
// +build !wireinject

package engine

import (
	"github.com/emm035/nats-secrets-engine/internal/account"
	"github.com/emm035/nats-secrets-engine/internal/operator"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// Injectors from wire.go:

func NewBackend() (logical.Backend, error) {
	service := &operator.Service{}
	logger := NewLogger()
	userCredsService := &account.UserCredsService{
		Logger: logger,
	}
	paths := operator.NewPaths(service)
	userCredentialsSecret := account.NewUserCredentialsSecret(userCredsService)
	accountService := &account.Service{
		Secret: userCredentialsSecret,
		Logger: logger,
	}
	accountPaths := account.NewPaths(accountService)
	v := NewPaths(paths, accountPaths)
	v2 := NewSecrets(userCredentialsSecret)
	frameworkBackend := NewNatsEngine(service, userCredsService, v, v2)
	return frameworkBackend, nil
}

// wire.go:

func NewPaths(operator2 operator.Paths, account2 account.Paths) []*framework.Path {
	return framework.PathAppend(operator2, account2)
}

func NewSecrets(ucrds account.UserCredentialsSecret) []*framework.Secret {
	return []*framework.Secret{
		ucrds.Secret,
	}
}
