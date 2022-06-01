
plugin
	go build -o bin/nats ./cmd/nats-secrets-engine

clean:
	rm -rf bin
	rm -f nats-secrets-engine

test:
	go test -v -count 1 ./...

# Dependency injection

wire: install-wire
	wire gen ./internal/engine

install-wire:
	command -v wire >> /dev/null || go install github.com/google/wire/cmd/wire@latest

# Linting

lint: install-golangci-lint
	golangci-lint run

install-golangci-lint:
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.46.2
