check_all: check check_openssl check_rust_crypto
check: test lint
check_openssl: lint_with_openssl build_with_openssl test_with_openssl
check_rust_crypto: lint_with_rust_crypto build_with_rust_crypto test_with_rust_crypto

test:
	cargo test

build:
	cargo build

lint:
	cargo clippy

fix:
	cargo fix --allow-dirty --allow-staged
	cargo fmt

build_with_openssl:
	cd radius && cargo build --verbose --no-default-features --features openssl

test_with_openssl:
	cd radius && cargo test --verbose --no-default-features --features openssl

lint_with_openssl:
	cd radius && cargo clippy --verbose --no-default-features --features openssl

build_with_rust_crypto:
	cd radius && cargo build --verbose --no-default-features --features rust-crypto

test_with_rust_crypto:
	cd radius && cargo test --verbose --no-default-features --features rust-crypto

lint_with_rust_crypto:
	cd radius && cargo clippy --verbose --no-default-features --features rust-crypto

