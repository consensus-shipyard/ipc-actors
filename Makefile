build:
	cargo build -Z unstable-options --release --target=wasm32-unknown-unknown --workspace --out-dir output

.PHONY: build
