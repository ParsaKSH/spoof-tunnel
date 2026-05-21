.PHONY: all core panel frontend backend clean test rust xdp-ebpf xdp-loader

# ── Build All ──
all: core panel

# ── XDP/eBPF (kernel-side program, needs nightly) ──
xdp-ebpf:
	cd rust/xdp-ebpf && cargo +nightly build \
		--target bpfel-unknown-none \
		-Z build-std=core \
		--release

# ── XDP Loader (userspace, links into Go binary) ──
xdp-loader: xdp-ebpf
	cd rust/xdp-loader && cargo build --release

# ── Core transport (existing Rust FFI) ──
rust:
	cd rust && cargo build --release

# ── Core binary (Go + Rust FFI + XDP) ──
core: rust xdp-loader
	CGO_ENABLED=1 go build \
		-ldflags "-r $(PWD)/rust/xdp-loader/target/release" \
		-o spoof ./cmd/spoof/

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
test: rust xdp-ebpf
	cd rust && cargo test
	CGO_ENABLED=1 go test ./internal/...
	cd panel/backend && go vet ./...

# ── Clean ──
clean:
	cd rust && cargo clean
	cd rust/xdp-ebpf && cargo clean 2>/dev/null || true
	cd rust/xdp-loader && cargo clean 2>/dev/null || true
	rm -f spoof spoof-panel
	rm -rf panel/frontend/.next panel/frontend/out
	rm -rf panel/backend/cmd/panel/web
