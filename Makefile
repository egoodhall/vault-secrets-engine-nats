
plugin: wire-gen
	go build -o plugins/nats ./cmd/nats

clean:
	rm -rf plugins
	rm -f nats

wire-gen: wire-check
	wire gen .

wire-check:
	@command -v wire >> /dev/null || go install github.com/google/wire/cmd/wire@latest
