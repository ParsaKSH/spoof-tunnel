.PHONY: all rust go clean test

all: rust go

rust:
	cd rust && cargo build --release

go: rust
	CGO_ENABLED=1 go build -o spoof ./cmd/spoof/

clean:
	cd rust && cargo clean
	rm -f spoof

test: rust
	cd rust && cargo test
	CGO_ENABLED=1 go test ./internal/...
