# xtask

This directory contains the Rust-based task runner for rs-matter development tasks, particularly for running ConnectedHomeIP YAML integration tests.

## Purpose

The `xtask` tool provides a unified, cross-platform way for developers to:
- Set up the ConnectedHomeIP testing environment
- Build rs-matter examples
- Run integration tests against the official Matter test suite

## Usage

From the rs-matter root directory:

```bash
# Run via cargo alias (recommended)
cargo xtask --help

# Or run directly
cd xtask && cargo run -- --help
```

## Architecture

This tool is deliberately **not** included in the rs-matter workspace to:
- Keep it as a standalone development tool
- Avoid dependency conflicts with the main rs-matter codebase
- Allow it to have its own dependencies optimized for development tasks

## Commands

- `itest-setup`: One-time setup of ConnectedHomeIP environment
- `build`: Build rs-matter examples 
- `itest`: Run integration tests

See the main documentation in [`.github/workflows/README.md`](../.github/workflows/README.md) for complete usage instructions.