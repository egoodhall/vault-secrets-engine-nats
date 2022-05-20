package main

import (
	"os"

	natsengine "github.com/emm035/vault-plugin-secrets-nats"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/plugin"
)

func main() {
	meta := new(api.PluginAPIClientMeta)
	flags := meta.FlagSet()
	flags.Parse(os.Args[1:])

	tlsc := meta.GetTLSConfig()
	tlsprov := api.VaultPluginTLSProvider(tlsc)

	err := plugin.Serve(&plugin.ServeOpts{
		BackendFactoryFunc: natsengine.Factory,
		TLSProviderFunc:    tlsprov,
	})
	if err != nil {
		logger := hclog.New(&hclog.LoggerOptions{})
		logger.Error("plugin shutting down", "error", err)
		os.Exit(1)
	}
}
