#!/usr/bin/env bash

## Packages to use lld linker
cargo install -f cargo-binutils
rustup component add llvm-tools-preview
sudo apt-get install lld clang

# Inner development loop
cargo install cargo-watch

# code coverage
cargo install cargo-tarpaulin

# linting
eustup component add clippy
# cargo clippy
## In CI
# cargo clippy -- -D warnings


# Formatting
rustup component add rustfmt
#cargo fmt
## In CI
#cargo fmt -- --check


# Security Vulnerabilities
cargo install cargo-audit
#cargo audit
