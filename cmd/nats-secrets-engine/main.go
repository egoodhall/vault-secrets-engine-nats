package main

import (
	"os"

	"github.com/egoodhall/vault-secrets-engine-nats/internal/engine"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/plugin"
)

func main() {
	meta := new(api.PluginAPIClientMeta)
	flags := meta.FlagSet()
	err := flags.Parse(os.Args[1:])
	if err != nil {
		logger := hclog.New(&hclog.LoggerOptions{})
		logger.Error("plugin shutting down", "error", err)
		os.Exit(1)
	}

	tlsc := meta.GetTLSConfig()
	tlsprov := api.VaultPluginTLSProvider(tlsc)

	err = plugin.Serve(&plugin.ServeOpts{
		BackendFactoryFunc: engine.Factory,
		TLSProviderFunc:    tlsprov,
	})
	if err != nil {
		logger := hclog.New(&hclog.LoggerOptions{})
		logger.Error("plugin shutting down", "error", err)
		os.Exit(1)
	}
}
