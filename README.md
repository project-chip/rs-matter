# rs-matter: The Rust Implementation of Matter

![experimental](https://img.shields.io/badge/status-Experimental-red)
[![license](https://img.shields.io/badge/license-Apache2-green.svg)](https://raw.githubusercontent.com/project-chip/matter-rs/main/LICENSE)
[![CI](https://github.com/project-chip/matter-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/project-chip/matter-rs/actions/workflows/ci.yml)
[![CI - TLV](https://github.com/project-chip/matter-rs/actions/workflows/ci-tlv-tool.yml/badge.svg)](https://github.com/project-chip/matter-rs/actions/workflows/ci-tlv-tool.yml)
[![crates.io](https://img.shields.io/crates/v/rs-matter.svg)](https://crates.io/crates/rs-matter)
[![Matrix](https://img.shields.io/matrix/matter-rs:matrix.org?label=join%20matrix&color=BEC5C9&logo=matrix)](https://matrix.to/#/#matter-rs:matrix.org)

## Build

### Building the library

```
$ cargo build
```

### Building and running the On-Off Light example (Linux, MacOS X)

```
$ cargo run --example onoff_light
```

### Building all examples (Linux, MacOS X)

```
$ cargo build --examples
```

NOTE: If you are on Linux and are running the Avahi daemon, you might want to build with:
```
$ cargo build --examples --features zeroconf
```

### Unit Tests
```
$ cargo test -- --test-threads 1
```

## Test

With the [`chip-tool` (the current tool for testing Matter)](https://github.com/project-chip/connectedhomeip/blob/master/examples/chip-tool/README.md) use the Ethernet commissioning mechanism:

```
$ chip-tool pairing code 12344321 <Pairing-Code>
```

Or alternatively:

```
$ chip-tool pairing ethernet 12344321 123456 0 <IP-Address> 5540
```

Interact with the device

```
# Read server-list
$ chip-tool descriptor read server-list 12344321 0

# Read On/Off status
$ chip-tool onoff read on-off 12344321 1

# Toggle On/Off by invoking the command
$ chip-tool onoff on 12344321 1
```

# Test with Google/Apple/Alexa controllers

All of these should work. Follow the instructions in your controller phone app.

## Notes

The `rs-matter` implementation is relatively complete, yet still a work-in-progress and does not yet fully implement all Matter system clusters.

With that said, making it run against the Matter C++ SDK Test Suite is in progress.
