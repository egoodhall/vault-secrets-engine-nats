package natsengine

import "github.com/hashicorp/go-hclog"

func NewLogger() hclog.Logger {
	return hclog.New(&hclog.LoggerOptions{})
}
