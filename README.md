# ![alt text](https://avatars.githubusercontent.com/u/61027988?s=48&v=4 "rs-matter") rs-matter

[![license](https://img.shields.io/badge/license-Apache2-green.svg)](https://raw.githubusercontent.com/project-chip/rs-matter/main/LICENSE)
[![CI](https://github.com/project-chip/rs-matter/actions/workflows/ci.yml/badge.svg)](https://github.com/project-chip/rs-matter/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/rs-matter.svg)](https://crates.io/crates/rs-matter)
[![Matrix](https://img.shields.io/matrix/rs-matter:matrix.org?label=join%20matrix&color=BEC5C9&logo=matrix)](https://matrix.to/#/#rs-matter:matrix.org)

## What is it exactly?

**A pure-Rust, `no_std`, no-alloc, async-first, extensible and safe implementation of the [Matter protocol](https://csa-iot.org/all-solutions/matter/)**.

Scales from bare-metal MCUs with 1MB flash and 256KB RAM to ARM embedded Linux and bigger iron!

Rather than a shrink-wrapped solution, it is first and formeost - a **toolkit**.
Users are free to consume all of the APIs, including the provided system clusters, or only pick up bits and pieces. As in:
* ... custom IP network implementation and BLE GATT device implementation;
* ... custom Exchange responders;
* ... custom mDNS provider;
* ... re-using the transport layer and Secure Channel, but implementing their own Data Model;
* ... flexible polling of the `rs-matter` futures as e.g. separate tasks in their async executor of choice;
* ... or just using the shrink-wrapped [`rs-matter-stack`](https://github.com/sysgrok/rs-matter-stack) arrangement and its down-stream crates;
* ... and so on.

## I just want to run Matter on my MCU!

* To run `rs-matter` on baremetal MCUs with [Embassy](https://github.com/embassy-rs/embassy), look at [`rs-matter-embassy`](https://github.com/sysgrok/rs-matter-embassy). Currently supported MCUs:
  *  Espressif ESP32XX
  *  Nordic NRF52840
  *  RP2040 Pico and RP2040 Pico W
* To run `rs-matter` on top of the [ESP-IDF](https://github.com/esp-rs/esp-idf-svc) with Espressif MCUs, look at [`esp-idf-matter`](https://github.com/sysgrok/esp-idf-matter)

## Documentation

We'll have an `rs-matter` Rust Book in future, but in the meantime - look at the [examples](examples), [docs](docs), as well as the code documentation.
Use the [discussions](https://github.com/project-chip/rs-matter/discussions) to ask questions.

## Status Quo

`rs-matter` is *relatively feature complete*, and can be used to implement both accessories (the typical use case),
as well as controllers and commissioners.

With that said, the API is not stable and is likely to still see some backwards-incompatible changes,
though the blast radius should be more limited now.

Provisioning and operating under the major Smart Home controllers should work just fine. Following are tested to work:
- Google Home
- Apple HomeKit
- Alexa
- Home Assistant
- Samsung SmartThings
- IKEA Dirigera Hub

## Next steps

* Even more memory optimizations (`rs-matter` currently sits at ~ 60KB .bss and ~ 20KB stack in its smallest configuration);
* More Flash trimming (a minimal firmware with `rs-matter-embassy` and Thread + BLE Coex for the NRF-52840 weights ~ 600 to 650KB);
* Enable more ConnectedHomeIP YAML and Python tests;
* Work towards certification of a product on top of `rs-matter`.

Also look at all [open issues](https://github.com/project-chip/rs-matter/issues).

## Continuous Integration

`rs-matter` includes comprehensive CI testing:

- **Standard CI**: Runs on every push and PR with build, test, linting across multiple feature combinations
- **ConnectedHomeIP Integration**: Native Rust tooling via `xtask` for running official Matter test cases
  - Run locally during development: `cargo xtask itest`
  - Automated nightly CI execution
  - Iterative test enablement workflow for developers

## Nix support

`rs-matter` provides nix files for setting up reproducible shells on systems using the nix package manager.
There are two different environments for different use-cases.

#### `devenv.nix`

This is used for normal development of applications.
To enter this shell, run `devenv shell` in the project root.
You can optionally follow this with your preferred shell e.g. `devenv shell zsh`.

This requires [devenv](https://devenv.sh/) to be installed on your system.
For nix managed systems, add `pkgs.devenv` to `environment.systemPackages`.

#### `shell.nix`

This is for cases where tools expect a standard Linux filesystem layout (FHS).
Use this shell when running `cargo xtask itest` (see testing topics below) as it sets up `connectedhomeip` which expects a FHS layout.
To enter this shell, run `nix-shell` in the project root.

## How does it look like?

See the [examples](examples).

Note that using the "Matter Stack" metaphor of [`rs-matter-stack`](https://github.com/ivmarkov/rs-matter-stack) / [`rs-matter-embassy`](https://github.com/ivmarkov/rs-matter-embassy) / [`esp-idf-matter`](https://github.com/ivmarkov/esp-idf-matter) results in less bootstrapping boilerplate.

```rust
/*
 *
 *    Copyright (c) 2025-2026 Project CHIP Authors
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

//! An example Matter accessory that implements a Speaker device over Ethernet.
//! Demonstrates how to make use of the `LevelControl` and `OnOff` cluster handlers,
//! and how to run a Matter device over Ethernet with mDNS discovery.

use core::pin::pin;

use std::net::UdpSocket;

use embassy_futures::select::select4;

use rand::RngCore;
use rs_matter::crypto::{default_crypto, Crypto};
use rs_matter::dm::clusters::app::level_control::{
    self, test::TestLevelControlDeviceLogic, AttributeDefaults, LevelControlHandler,
    LevelControlHooks, OptionsBitmap,
};
use rs_matter::dm::clusters::app::on_off::{
    self, test::TestOnOffDeviceLogic, OnOffHandler, OnOffHooks,
};
use rs_matter::dm::clusters::desc::{self, ClusterHandler as _};
use rs_matter::dm::devices::test::{DAC_PRIVKEY, TEST_DEV_ATT, TEST_DEV_COMM, TEST_DEV_DET};
use rs_matter::dm::devices::DEV_TYPE_SMART_SPEAKER;
use rs_matter::dm::endpoints;
use rs_matter::dm::networks::eth::EthNetwork;
use rs_matter::dm::networks::SysNetifs;
use rs_matter::dm::{Async, DataModel, Dataver, Endpoint, EpClMatcher, Node};
use rs_matter::error::Error;
use rs_matter::im::{EthInteractionModelState, InteractionModel};
use rs_matter::pairing::qr::QrTextType;
use rs_matter::pairing::DiscoveryCapabilities;
use rs_matter::persist::DirKvBlobStore;
use rs_matter::respond::DefaultResponder;
use rs_matter::sc::pase::MAX_COMM_WINDOW_TIMEOUT_SECS;
use rs_matter::tlv::Nullable;
use rs_matter::transport::exchange::MatterBuffers;
use rs_matter::transport::MATTER_SOCKET_BIND_ADDR;
use rs_matter::utils::select::Coalesce;
use rs_matter::{clusters, devices, root_endpoint, Matter, MATTER_PORT};

#[path = "../common/mdns.rs"]
mod mdns;

fn main() -> Result<(), Error> {
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "info"),
    );

    // Create the Matter object
    let matter = Matter::new(&TEST_DEV_DET, TEST_DEV_COMM, &TEST_DEV_ATT, MATTER_PORT);

    // Persistence
    let store = DirKvBlobStore::new_default();

    // Create the transport buffers
    let buffers: MatterBuffers = MatterBuffers::new();

    // Create the data model state (subscriptions, events, network store).
    let mut state: EthInteractionModelState =
        EthInteractionModelState::new(EthNetwork::new_default());

    // Bind the KV access object (the KV scratch buffer lives in `Matter`).
    let kv = matter.kv(store);

    // Re-hydrate the `Matter` instance and the data model state (event-number epoch).
    futures_lite::future::block_on(matter.load_persist(&kv))?;
    futures_lite::future::block_on(state.load_persist(&kv))?;

    // Create the crypto instance
    let crypto = default_crypto(rand::thread_rng(), DAC_PRIVKEY);

    let mut rand = crypto.rand()?;

    // OnOff cluster setup
    let on_off_handler = on_off::OnOffHandler::new(
        Dataver::new_rand(&mut rand),
        1,
        TestOnOffDeviceLogic::new(true),
    );

    // LevelControl cluster setup
    let level_control_handler = LevelControlHandler::new(
        Dataver::new_rand(&mut rand),
        1,
        TestLevelControlDeviceLogic::new(),
        AttributeDefaults {
            on_level: Nullable::some(42),
            options: OptionsBitmap::from_bits(OptionsBitmap::EXECUTE_IF_OFF.bits()).unwrap(),
            on_off_transition_time: 0,
            on_transition_time: Nullable::none(),
            off_transition_time: Nullable::none(),
            default_move_rate: Nullable::none(),
        },
    );

    // Cluster wiring, validation and initialisation
    on_off_handler.init(Some(&level_control_handler));
    level_control_handler.init(Some(&on_off_handler));

    // Create the Data Model instance
    let im = InteractionModel::new(
        &matter,
        &crypto,
        &buffers,
        data_model(rand, &on_off_handler, &level_control_handler),
        &kv,
        &state,
    );

    // Create a default responder capable of handling up to 3 subscriptions
    // All other subscription requests will be turned down with "resource exhausted"
    let responder = DefaultResponder::new(&im);

    // Run the responder with up to 4 handlers (i.e. 4 exchanges can be handled simultaneously)
    // Clients trying to open more exchanges than the ones currently running will get "I'm busy, please try again later"
    let mut respond = pin!(responder.run::<4, 4>());

    // Run the background job of the data model
    let mut im_job = pin!(im.run());

    // Create the Matter UDP socket
    let socket = async_io::Async::<UdpSocket>::bind(MATTER_SOCKET_BIND_ADDR)?;

    // Run the Matter and mDNS transports
    let mut mdns = pin!(mdns::run_mdns(&matter, &crypto));
    let mut transport = pin!(matter.run(&crypto, &socket, &socket, &socket));

    if !matter.is_commissioned() {
        // If the device is not commissioned yet, print the QR text and code to the console
        // and enable basic commissioning

        matter.print_standard_qr_text(DiscoveryCapabilities::IP)?;
        matter.print_standard_qr_code(QrTextType::Unicode, DiscoveryCapabilities::IP)?;

        matter.open_basic_comm_window(MAX_COMM_WINDOW_TIMEOUT_SECS, &crypto, &())?;
    }

    // Combine all async tasks in a single one
    let all = select4(&mut transport, &mut mdns, &mut respond, &mut im_job).coalesce();

    // Run with a simple `block_on`. Any local executor would do.
    futures_lite::future::block_on(all)
}

/// The Node meta-data describing our Matter device.
const NODE: Node<'static> = Node {
    endpoints: &[
        root_endpoint!(eth),
        Endpoint::new(
            1,
            devices!(DEV_TYPE_SMART_SPEAKER),
            clusters!(
                desc::DescHandler::CLUSTER,
                TestOnOffDeviceLogic::CLUSTER,
                TestLevelControlDeviceLogic::CLUSTER
            ),
        ),
    ],
};

/// The Data Model handler + meta-data for our Matter device.
/// The handler is the root endpoint 0 handler plus the Speaker handler.
fn data_model<'a, LH: LevelControlHooks, OH: OnOffHooks>(
    mut rand: impl RngCore + Copy,
    on_off: &'a OnOffHandler<'a, OH, LH>,
    level_control: &'a LevelControlHandler<'a, LH, OH>,
) -> impl DataModel + 'a {
    (
        NODE,
        endpoints::EthSysHandlerBuilder::new()
            .netif_diag(&SysNetifs)
            .build(rand)
            .chain(
                EpClMatcher::new(Some(1), Some(desc::DescHandler::CLUSTER.id)),
                Async(desc::DescHandler::new(Dataver::new_rand(&mut rand)).adapt()),
            )
            .chain(
                EpClMatcher::new(Some(1), Some(TestLevelControlDeviceLogic::CLUSTER.id)),
                level_control::HandlerAsyncAdaptor(level_control),
            )
            .chain(
                EpClMatcher::new(Some(1), Some(TestOnOffDeviceLogic::CLUSTER.id)),
                on_off::HandlerAsyncAdaptor(on_off),
            ),
    )
}
```

## Build

### Building the library and all examples

```sh
$ cargo build --features zeroconf
```

#### **NOTE**: mDNS issues (e.g. "running the example fails with strange error messages mentioning mDNS").

These days mDNS is still a PITA especially on Windows, but not only.

`rs-matter` currently offers no less than 5 (five!) mDNS implementations:
- Three well-supported ones - `avahi`, `resolve` and `builtin` -
for production use-cases on embedded MCUs and embedded Linux;
- ...as well as two legacy ones - `zeroconf` and `astro-dnssd` - which are kept around
for compatibility with Windows and MacOSX; look inside `rs-matter/rs-matter/src/transport/network/mdns` for more details on those.

The TL;DR is, rather than building with `--features zeroconf` everywhere, you can try:
- On Linux: all of the above, but `--features avahi` and `--features resolve` are your best bet in production;
- On MacOSX: `--features astro-dnssd` is known to work fine;
- On Windows: try the built-in mDNS resolver.

### Unit tests and internal E2E tests
```sh
cargo test -- --test-threads 1
```

### E2E/acceptance tests form the C++ SDK
```sh
cargo xtask itest
```

## Test with `chip-tool`

With the [`chip-tool` (the tool for testing Matter)](https://github.com/project-chip/connectedhomeip/blob/master/examples/chip-tool/README.md) run one of our examples, and then use the Ethernet commissioning mechanism:

```sh
chip-tool pairing code 12344321 <Pairing-Code>
```

Or alternatively:

```sh
chip-tool pairing ethernet 12344321 123456 0 <IP-Address> 5540
```

Interact with the device

```sh
# Read server-list
chip-tool descriptor read server-list 12344321 0

# Read On/Off status
chip-tool onoff read on-off 12344321 1

# Toggle On/Off by invoking the command
chip-tool onoff on 12344321 1
```

# Test with Google, Apple, Alexa and other commercial controllers

All of these should work. Follow the instructions in your controller phone app.
