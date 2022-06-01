package account

import "github.com/google/wire"

var ProviderSet = wire.NewSet(
	NewPaths,
	NewUserCredentialsSecret,
	wire.Struct(new(Service), "*"),
	wire.Struct(new(UserCredsService), "*"),
)
