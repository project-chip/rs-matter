# ConnectedHomeIP Integration Tests

This directory contains the GitHub Actions workflow for running rs-matter against the official ConnectedHomeIP YAML test suite. The workflow uses a Rust-based `xtask` tool to enable both automated CI testing and local developer workflows.

## Quick Start for Developers

The integration tests are implemented using a custom `xtask` tool that allows developers to run ConnectedHomeIP YAML tests locally:

```bash
# One-time setup: Install ConnectedHomeIP and build chip-tool
cargo xtask itest-setup

# Run integration tests (builds rs-matter automatically)
cargo xtask itest

# Run specific tests
cargo xtask itest TestAttributesById TestBasicInformation

# Run tests with release build
cargo xtask itest --profile release

# Just build rs-matter examples
cargo xtask build

# Get help for any command
cargo xtask --help
cargo xtask itest --help
```

## Available Commands

### `itest-setup`
Sets up the ConnectedHomeIP environment for integration testing:
- Clones the ConnectedHomeIP repository (if not already present)
- Sets up Python virtual environment with required dependencies
- Builds chip-tool (if not cached)

Options:
- `--connectedhomeip-ref <REF>`: Specify ConnectedHomeIP branch/tag/commit (default: master)
- `--force-rebuild`: Force rebuild even if cached

### `build`
Builds rs-matter examples with the specified configuration:
- Builds the `onoff_light` example by default
- Configurable build profile and features

Options:
- `--profile <PROFILE>`: Build profile (debug or release, default: debug)
- `--features <FEATURES>`: Additional cargo features

### `itest`
Runs ConnectedHomeIP YAML integration tests:
- Automatically builds rs-matter unless `--skip-build` is used
- Runs specified tests or all enabled tests if none specified

Options:
- `--profile <PROFILE>`: Build profile for rs-matter examples (default: debug)
- `--timeout <TIMEOUT>`: Timeout for each test in seconds (default: 120)
- `--skip-build`: Skip building rs-matter (assume it's already built)

## Configuring Tests

Currently enabled tests are hardcoded in the `xtask` tool. To modify which tests run by default, edit the `get_enabled_tests()` function in `xtask/src/main.rs`.

Available tests include:
- `TestAttributesById` (currently enabled)
- `TestAccessControlCluster` 
- `TestBasicInformation`

## Developer Workflow

The typical developer workflow for working with integration tests:

1. **Initial setup** (one time):
   ```bash
   cargo xtask itest-setup
   ```

2. **Iterative development**:
   ```bash
   # Run a specific test
   cargo xtask itest TestBasicInformation
   
   # Fix rs-matter implementation based on test results
   # ... make code changes ...
   
   # Run the test again (rs-matter will be rebuilt automatically)
   cargo xtask itest TestBasicInformation
   ```

3. **Adding new tests**:
   - Add the test name to the enabled tests list in `xtask/src/main.rs`
   - Run the test to see if it passes
   - If it fails, create an issue and fix the rs-matter implementation
   - Continue until the test passes

## System Requirements

Before running integration tests, ensure you have:
- **Rust toolchain** (stable)
- **Python 3** with pip and venv
- **Git**
- **System libraries**: libdbus-1-dev, pkg-config

The `xtask` tool will check for these dependencies and report any missing ones.

## GitHub Actions Workflow

The automated CI workflow (`connectedhomeip-tests.yml`) uses the same `xtask` tool:

1. **Nightly Schedule**: Runs every night at 2:00 AM UTC
2. **Manual Trigger**: Can be triggered manually with configurable ConnectedHomeIP reference
3. **Caching**: Caches both ConnectedHomeIP builds and Rust dependencies
4. **Artifact Collection**: Uploads test results and logs on failure

### Manual Workflow Execution

You can manually trigger the workflow via GitHub's web interface or the `gh` CLI:

```bash
# Trigger with default settings (master branch of ConnectedHomeIP)
gh workflow run connectedhomeip-tests.yml

# Trigger with specific ConnectedHomeIP reference
gh workflow run connectedhomeip-tests.yml --field connectedhomeip_ref=v1.3-branch
```

## Troubleshooting

### Common Issues

1. **Missing system dependencies**:
   ```bash
   sudo apt-get update
   sudo apt-get install -y libdbus-1-dev pkg-config git python3 python3-pip python3-venv
   ```

2. **ConnectedHomeIP build failures**:
   ```bash
   # Force rebuild of ConnectedHomeIP
   cargo xtask itest-setup --force-rebuild
   ```

3. **Python environment issues**:
   ```bash
   # Clean up and rebuild ConnectedHomeIP environment
   rm -rf connectedhomeip/venv
   cargo xtask itest-setup --force-rebuild
   ```

### Debug Output

For more verbose output during test execution, you can modify the log level in the xtask tool or run with RUST_LOG:

```bash
RUST_LOG=debug cargo xtask itest
```

### Test Data Location

Test data is stored in temporary directories (under `/tmp/`). If you need to examine test artifacts after a failure, check the console output for the specific temporary directory path.

## Architecture

The integration test system consists of:

1. **xtask tool** (`xtask/`): Rust-based task runner
   - Handles ConnectedHomeIP setup and environment management
   - Builds rs-matter examples with proper features
   - Executes YAML tests with proper environment variables

2. **GitHub Actions workflow** (`.github/workflows/connectedhomeip-tests.yml`):
   - Uses the xtask tool for all operations
   - Provides caching and artifact collection
   - Runs on schedule and manual triggers

3. **Integration with existing tooling**:
   - Uses the same ConnectedHomeIP test infrastructure as the original shell script
   - Maintains compatibility with chip-tool and test runners

This architecture ensures that developers can run the same tests locally that run in CI, enabling efficient debugging and development of Matter protocol compliance.