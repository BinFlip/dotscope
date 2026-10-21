# Makefile for dotscope development
# Provides convenient commands for common development tasks

# Doc tests link one binary per fenced example, and `[profile.release]` uses
# `lto = "fat"`, so each link is a whole-crate LTO job costing gigabytes of RAM. The
# harness defaults to one thread per core, which on a many-core machine means dozens of
# those at once and an out-of-memory freeze. Cap the concurrency instead; override with
# `make test-doc DOC_TEST_THREADS=n`.
#
# `.cargo/config.toml` sets `RUST_TEST_THREADS = "8"` so that guard also holds for anyone
# who runs cargo directly instead of going through this file. This default matches it:
# a value above the config's guard would silently defeat it, since an explicit
# `-- --test-threads=N` always wins over cargo's `[env]`.
#
# Unit tests are cheap per test and want every core, so the test tiers export their own
# `RUST_TEST_THREADS` to opt back out: cargo's `[env]` deliberately does not override a
# variable that is already set.
DOC_TEST_THREADS ?= 8
TEST_THREADS ?= $(shell nproc 2>/dev/null || echo 8)

# The coverage targets build the way the `test-full` tier does (see `.cargo/config.toml`).
# `--lib --bins --tests` leaves out doc tests, which have their own target because they need a
# concurrency cap the tiers do not.
TEST_FLAGS := --workspace --profile ci-test --features z3 --no-fail-fast

.PHONY: help build test test-quick test-full test-oracle test-doc test-coverage clean fmt clippy doc bench fuzz install coverage audit

# Default target
help:
	@echo "Available targets:"
	@echo "  build       - Build the project"
	@echo "  test        - Run the full test tier"
	@echo "  test-quick  - Unit tests and the fast integration tests (no \`full\` modules)"
	@echo "  test-full   - test-quick plus the packer suites, runtime corpora, codegen validation"
	@echo "  test-oracle - test-full, failing when an external .NET tool is missing"
	@echo "  test-doc    - Run doc tests (memory-bounded; see DOC_TEST_THREADS)"
	@echo "  clean       - Clean build artifacts"
	@echo "  fmt         - Format code"
	@echo "  clippy      - Run clippy lints"
	@echo "  doc         - Generate documentation"
	@echo "  bench       - Run benchmarks"
	@echo "  fuzz        - Run fuzzing (requires nightly)"
	@echo "  install     - Install development tools"
	@echo "  coverage    - Generate coverage report"
	@echo "  audit       - Run security audit"
	@echo "  check-all   - Run all checks (fmt, clippy, test, audit)"

# Build the project
build:
	cargo build --workspace --all-features

# Build release version
build-release:
	cargo build --release --all-features

# Run tests
#
# Test tiers. The tiers are cargo aliases in `.cargo/config.toml`; these targets, CI and
# GitLab all call them by name, so every front end runs the same tests for a tier.
#
# An optimised profile is mandatory, not a speed preference: the sample-driven integration
# tests run the full detection -> SSA -> pass-pipeline -> codegen path over real packed
# binaries, which takes hours unoptimised and tens of seconds optimised. `ci-test` is
# release with debug assertions and overflow checks on (see the workspace Cargo.toml), so
# the invariants release compiles out are checked here.
#
# quick:  the unit tests and the integration tests outside a `full` module.
# full:   quick plus the `full` modules (packer suites, runtime corpora, codegen validation),
#         the lift verification sweep and the fuzz regression replay.
# oracle: full with DOTSCOPE_REQUIRE_TOOLS=1: a test that needs dotnet, mono, ildasm or
#         peverify fails when the tool is missing instead of skipping.
test-quick:
	RUST_TEST_THREADS=$(TEST_THREADS) cargo test-quick

test-full:
	RUST_TEST_THREADS=$(TEST_THREADS) cargo test-full

test-oracle:
	DOTSCOPE_REQUIRE_TOOLS=1 RUST_TEST_THREADS=$(TEST_THREADS) cargo test-full

test: test-full

# Run doc tests
#
# Split out from `test` and concurrency-capped: see DOC_TEST_THREADS at the top of this file.
test-doc:
	cargo test --workspace --release --all-features --doc -- --test-threads=$(DOC_TEST_THREADS)

# Coverage of the full tier, as lcov (CI uploads it to Codecov)
test-coverage:
	RUST_TEST_THREADS=$(TEST_THREADS) cargo llvm-cov $(TEST_FLAGS) --exclude dotscope-cli --lib --bins --tests --lcov --output-path lcov.info
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
	cargo clippy --workspace --all-features --all-targets -- -D warnings

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
# Runs every target in turn, each seeded from the committed crash corpus. Override the target
# with `make fuzz FUZZ_TARGETS=signatures`, or the duration with `FUZZ_TIME=300`.
FUZZ_TARGETS ?= cilobject assemblyview signatures customattributes methodbody emulation
FUZZ_TIME ?= 60
FUZZ_RSS_LIMIT_MB ?= 4096

fuzz:
	@for t in $(FUZZ_TARGETS); do \
		echo "=== fuzzing $$t ==="; \
		mkdir -p dotscope/fuzz/corpus/$$t; \
		cp dotscope/tests/samples/fuzz-regressions/* dotscope/fuzz/corpus/$$t/ 2>/dev/null || true; \
		(cd dotscope/fuzz && cargo +nightly fuzz run $$t -- \
			-max_total_time=$(FUZZ_TIME) -rss_limit_mb=$(FUZZ_RSS_LIMIT_MB)) || exit 1; \
	done

# Install development tools
install:
	rustup component add clippy rustfmt llvm-tools-preview
	cargo install cargo-fuzz cargo-audit cargo-outdated cargo-llvm-cov

# Coverage of the full tier, as HTML
coverage:
	RUST_TEST_THREADS=$(TEST_THREADS) cargo llvm-cov $(TEST_FLAGS) --exclude dotscope-cli --lib --bins --tests --html
	@echo "HTML coverage report generated at target/llvm-cov/html/index.html"

# Run security audit
audit:
	cargo audit

# Check for outdated dependencies
outdated:
	cargo outdated

# Run all checks
check-all: fmt-check clippy test test-doc audit
	@echo "All checks passed!"

# Prepare for release
release-check:
	cargo publish -p dotscope --dry-run --all-features
	@echo "Release check completed successfully"

# Quick development cycle
dev: fmt clippy test
	@echo "Development cycle completed"

# CI simulation (run what CI runs)
ci: fmt-check clippy test test-doc doc
	@echo "CI simulation completed"
