
plugin: wire-gen
	go build -o bin/nats ./cmd/nats-secrets-engine

clean:
	rm -rf bin
	rm -f nats-secrets-engine

wire-gen: wire-check
	wire gen ./internal/engine

wire-check:
	@command -v wire >> /dev/null || go install github.com/google/wire/cmd/wire@latest
