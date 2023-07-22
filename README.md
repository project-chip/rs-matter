# rs-matter: The Rust Implementation of Matter

![experimental](https://img.shields.io/badge/status-Experimental-red) [![license](https://img.shields.io/badge/license-Apache2-green.svg)](https://raw.githubusercontent.com/project-chip/matter-rs/main/LICENSE)

[![Test Linux (OpenSSL)](https://github.com/project-chip/matter-rs/actions/workflows/test-linux-openssl.yml/badge.svg)](https://github.com/project-chip/matter-rs/actions/workflows/test-linux-openssl.yml)
[![Test Linux (mbedTLS)](https://github.com/project-chip/matter-rs/actions/workflows/test-linux-mbedtls.yml/badge.svg)](https://github.com/project-chip/matter-rs/actions/workflows/test-linux-mbedtls.yml)

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
