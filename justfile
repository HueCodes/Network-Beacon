# Default recipe
default: check

# Run all checks (fmt, clippy, test)
check: fmt clippy test

# Format code
fmt:
    cargo fmt

# Check formatting without modifying
fmt-check:
    cargo fmt --check

# Run clippy lints
clippy:
    cargo clippy --all-targets -- -D warnings

# Run tests
test:
    cargo test

# Run tests with output
test-verbose:
    cargo test -- --nocapture

# Build debug
build:
    cargo build

# Build release
release:
    cargo build --release

# Run the benchmark subcommand
bench flows="1000" events="100":
    cargo run --release -- benchmark --flows {{flows}} --events-per-flow {{events}}

# Run with a PCAP file
replay file:
    cargo run --release -- replay {{file}}

# Build Docker image
docker-build:
    docker build -t network-beacon .

# Clean build artifacts
clean:
    cargo clean

# Generate docs
doc:
    cargo doc --no-deps --open

# Run with live capture (requires sudo)
capture interface="en0":
    sudo cargo run --release -- capture -i {{interface}}
