.PHONY: all core panel frontend backend clean test

# ── Build All ──
all: core panel

# ── Core (spoof binary with Rust FFI) ──
rust:
	cd rust && cargo build --release

core: rust
	CGO_ENABLED=1 go build -o spoof ./cmd/spoof/

# ── Panel (frontend + backend) ──
panel: frontend backend

frontend:
	cd panel/frontend && npm ci --silent && npx next build
	rm -rf panel/backend/cmd/panel/web
	cp -r panel/frontend/out panel/backend/cmd/panel/web

backend: frontend
	cd panel/backend && CGO_ENABLED=0 go build -o ../../spoof-panel ./cmd/panel/

# ── Dev shortcuts ──
dev-frontend:
	cd panel/frontend && npm run dev

dev-backend:
	cd panel/backend && CGO_ENABLED=0 go build -o ../../spoof-panel ./cmd/panel/

# ── Test ──
test: rust
	cd rust && cargo test
	CGO_ENABLED=1 go test ./internal/...
	cd panel/backend && go vet ./...

# ── Clean ──
clean:
	cd rust && cargo clean
	rm -f spoof spoof-panel
	rm -rf panel/frontend/.next panel/frontend/out
	rm -rf panel/backend/cmd/panel/web
