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

### Building and running the example (Linux, MacOS X)

```
$ cargo run --example onoff_light --features async-io
```

## Test

With the `chip-tool` (the current tool for testing Matter) use the Ethernet commissioning mechanism:

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

## Functionality

- Secure Channel:
  - PASE
  - CASE
- Interactions:
  - Invoke Command(s), Read Attribute(s), Write Attribute(s)
- Commissioning:
  - over Ethernet
  - Network Commissioning Cluster
  - General Commissioning Cluster
  - Operational Certificates Cluster
- Some [TODO](TODO.md) are captured here

## Notes

The matter-rs project is a work-in-progress and does NOT yet fully implement Matter.
