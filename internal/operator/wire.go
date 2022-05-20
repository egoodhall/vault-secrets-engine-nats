package operator

import "github.com/google/wire"

var ProviderSet = wire.NewSet(
	NewPaths,
	wire.Struct(new(Service), "*"),
)
