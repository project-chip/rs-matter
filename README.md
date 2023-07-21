# matter-rs: The Rust Implementation of Matter

![experimental](https://img.shields.io/badge/status-Experimental-red) [![license](https://img.shields.io/badge/license-Apache2-green.svg)](https://raw.githubusercontent.com/project-chip/matter-rs/main/LICENSE)

[![Test Linux (OpenSSL)](https://github.com/project-chip/matter-rs/actions/workflows/test-linux-openssl.yml/badge.svg)](https://github.com/project-chip/matter-rs/actions/workflows/test-linux-openssl.yml)
[![Test Linux (mbedTLS)](https://github.com/project-chip/matter-rs/actions/workflows/test-linux-mbedtls.yml/badge.svg)](https://github.com/project-chip/matter-rs/actions/workflows/test-linux-mbedtls.yml)

## Important Note

All development work is now ongoing in two other branches ([no_std](https://github.com/project-chip/matter-rs/tree/no_std) and [sequential](https://github.com/project-chip/matter-rs/tree/sequential) - explained below). The plan is one of these two branches to become the new `main`.

We highly encourage users to try out both of these branches (there is a working `onoff_light` example in both) and provide feedback.

### [no_std](https://github.com/project-chip/matter-rs/tree/no_std)

The purpose of this branch - as the name suggests - is to introduce `no_std` compatibility to the `matter-rs` library, so that it is possible to target constrained environments like MCUs which more often than not have no support for the Rust Standard library (threads, network sockets, filesystem and so on).

We have been successful in this endeavour. The library now only requires Rust `core` and runs on e.g. ESP32 baremental Rust targets.
When `matter-rs` is used on targets that do not support the Rust Standard Library, user is expected to provide the following:

- A `rand` function that can fill a `&[u8]` slice with random data
- An `epoch` function (a "current time" utility); note that since this utility is only used for measuring timeouts, it is OK to provide a function that e.g. measures elapsed millis since system boot, rather than something that tries to adhere to the UNIX epoch (1/1/1970)
- An MCU-specific UDP stack that the user would need to connect to the `matter-rs` library

Besides just having `no_std` compatibility, the `no_std` branch does not need an allocator. I.e. all structures internal to the `matter-rs` librarty are statically allocated.

Last but not least, the `no_std` branch by itself does **not** do any IO. In other words, it is "compute only" (as in, "give me a network packet and I'll produce one or more that you have to send; how you receive/send those is up to you"). Ditto for persisting fabrics and ACLs - it is up to the user to listen the matter stack for changes to those and persist.

### [sequential](https://github.com/project-chip/matter-rs/tree/sequential)

The `sequential` branch builds on top of the work implemented in the `no_std` branch by utilizing code implemented as `async` functions and methods. Committing to `async` has multiple benefits:

- (Internal for the library) We were able to turn several explicit state machines into implicit ones (after all, `async` is primarily about generating state machines automatically based on "sequential" user codee that uses the async/await language constructs - hence the name of the branch)
- (External, for the user) The ergonomics of the Exchange API in this branch (in other words, the "transport aspect of the Matter CSA spec) is much better, approaching that of dealing with regular TCP/IP sockets in the Rust Standard Library. This is only possible by utilizing async functions and methods, because - let's not forget - `matter-rs` needs to run on MCUs where native threading and task scheduling capabilities might not even exist, hence "sequentially-looking" request/response interaction can only be expressed asynchronously, or with explicit state machines.
- Certain pending concepts are much easier to implement via async functions and methods:
- Re-sending packets which were not acknowledged by the receiver yet (the MRP protocol as per the Matter spec)
- The "initiator" side of an exchange (think client clusters)
- This branch provides facilities to implement asynchronous read, write and invoke handling for server clusters, which is beneficial in certain scenarios (i.e. brdige devices)

The `async` metaphor however comes with a bit higher memory usage, due to not enough optimizations being implemented yet in the rust language when the async code is transpiled to state machines.

## Build

### Building the library

```
$ cargo build
```

### Building and running the example (Linux, MacOS X)

```
$ cargo run --example onoff_light
```

### Building the example (Espressif's ESP-IDF)

* Install all build prerequisites described [here](https://github.com/esp-rs/esp-idf-template#prerequisites)
* Build with the following command line:
```
export MCU=esp32; export CARGO_TARGET_XTENSA_ESP32_ESPIDF_LINKER=ldproxy; export RUSTFLAGS="-C default-linker-libraries"; export WIFI_SSID=ssid;export WIFI_PASS=pass; cargo build --example onoff_light --no-default-features --features esp-idf --target xtensa-esp32-espidf -Zbuild-std=std,panic_abort
```
* If you are building for a different Espressif MCU, change the `MCU` variable, the `xtensa-esp32-espidf` target and the name of the `CARGO_TARGET_<esp-idf-target-uppercase>_LINKER` variable to match your MCU and its Rust target. Available Espressif MCUs and targets are:
  * esp32 / xtensa-esp32-espidf
  * esp32s2 / xtensa-esp32s2-espidf
  * esp32s3 / xtensa-esp32s3-espidf
  * esp32c3 / riscv32imc-esp-espidf
  * esp32c5 / riscv32imc-esp-espidf
  * esp32c6 / risxcv32imac-esp-espidf
* Put in `WIFI_SSID` / `WIFI_PASS` the SSID & password for your wireless router
* Flash using the `espflash` utility described in the build prerequsites' link above

### Building the example (ESP32-XX baremetal or RP2040)

Coming soon!

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
