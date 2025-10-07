# xtask

This directory contains the Rust-based task runner for `rs-matter` development tasks, particularly for running Chip YAML integration tests.

## Usage

From the rs-matter root directory:

```bash
cargo xtask --help
```

To get necessary environment configs (such as `gn`), you may also need to run:
```base
source matter_cpp/repo/scripts/bootstrap.sh
```