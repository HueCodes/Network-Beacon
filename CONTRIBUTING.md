# Contributing to Network-Beacon

## Getting Started

1. Install prerequisites: Rust 1.70+, libpcap-dev
2. Clone the repo and run `cargo test` to verify your setup
3. Install [just](https://github.com/casey/just) for task automation (optional)

## Development Workflow

```bash
# Run all checks (fmt + clippy + test)
just check

# Or individually
cargo fmt
cargo clippy --all-targets -- -D warnings
cargo test
```

## Code Style

- Run `cargo fmt` before committing
- All warnings are treated as errors (`-D warnings`)
- Follow existing patterns in the codebase
- Add tests for new detection logic

## Adding a New Detector

1. Create `src/your_detector.rs` with a config struct, detector struct, and detection methods
2. Add the config to `DetectionConfig` in `src/config.rs`
3. Wire it into `FlowData` in `src/analyzer.rs`
4. Add Prometheus counters in `src/metrics.rs` if applicable
5. Add tests covering detection thresholds and edge cases

## Testing

- Target: maintain 100+ unit tests
- Run `cargo test` — all tests must pass
- Use `tempfile` crate for tests that need filesystem access
- No network access required for tests (all tests use synthetic data)

## Commit Messages

Use conventional commits:

```
feat(module): short description
fix(module): short description
docs: short description
refactor(module): short description
test(module): short description
```

## Pull Requests

- One logical change per PR
- All CI checks must pass (fmt, clippy, test)
- Update CHANGELOG.md for user-facing changes
