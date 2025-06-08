# Makefile for dotscope development
# Provides convenient commands for common development tasks

.PHONY: help build test clean fmt clippy doc bench fuzz install coverage audit

# Default target
help:
	@echo "Available targets:"
	@echo "  build     - Build the project"
	@echo "  test      - Run all tests"
	@echo "  clean     - Clean build artifacts"
	@echo "  fmt       - Format code"
	@echo "  clippy    - Run clippy lints"
	@echo "  doc       - Generate documentation"
	@echo "  bench     - Run benchmarks"
	@echo "  fuzz      - Run fuzzing (requires nightly)"
	@echo "  install   - Install development tools"
	@echo "  coverage  - Generate coverage report"
	@echo "  audit     - Run security audit"
	@echo "  check-all - Run all checks (fmt, clippy, test, audit)"

# Build the project
build:
	cargo build --all-features

# Build release version
build-release:
	cargo build --release --all-features

# Run tests
test:
	cargo test --all-features --verbose

# Run tests with coverage
test-coverage:
	cargo llvm-cov --all-features --workspace --lcov --output-path lcov.info
	@echo "Coverage report generated at lcov.info"

# Clean build artifacts
clean:
	cargo clean
	rm -rf target/coverage/
	rm -f lcov.info coverage.xml

# Format code
fmt:
	cargo fmt --all

# Check formatting
fmt-check:
	cargo fmt --all -- --check

# Run clippy
clippy:
	cargo clippy --all-features --all-targets -- -D warnings

# Generate documentation
doc:
	cargo doc --all-features --no-deps --document-private-items

# Open documentation in browser
doc-open:
	cargo doc --all-features --no-deps --open

# Run benchmarks
bench:
	cargo bench --all-features

# Run fuzzing
fuzz:
	cd fuzz && cargo +nightly fuzz run cilobject -- -max_total_time=60

# Install development tools
install:
	rustup component add clippy rustfmt llvm-tools-preview
	cargo install cargo-fuzz cargo-audit cargo-outdated cargo-llvm-cov

# Generate coverage report
coverage:
	cargo llvm-cov --all-features --workspace --html
	@echo "HTML coverage report generated at target/llvm-cov/html/index.html"

# Run security audit
audit:
	cargo audit

# Check for outdated dependencies
outdated:
	cargo outdated

# Run all checks
check-all: fmt-check clippy test audit
	@echo "All checks passed!"

# Prepare for release
release-check:
	cargo publish --dry-run --all-features
	@echo "Release check completed successfully"

# Quick development cycle
dev: fmt clippy test
	@echo "Development cycle completed"

# CI simulation (run what CI runs)
ci: fmt-check clippy test doc
	@echo "CI simulation completed"
