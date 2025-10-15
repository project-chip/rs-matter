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
* ... re-using the transport layer and Secure Channel, but implementing their own Data Model;
* ... custom Exchange responders;
* ... custom mDNS provider;
* ... custom IP network implementation and BLE GATT device implementation;
* ... flexible polling of the `rs-matter` futures as e.g. separate tasks in their async executor of choice;
* ... or just using the shrink-wrapped [`rs-matter-stack`](https://github.com/ivmarkov/rs-matter-stack) arrangement and its down-stream crates;
* ... and so on.

## I just want to run Matter on my MCU!

* To run `rs-matter` on baremetal MCUs with [Embassy](https://github.com/embassy-rs/embassy), look at [`rs-matter-embassy`](https://github.com/ivmarkov/rs-matter-embassy). Currently supported MCUs:
  *  Espressif ESP32XX
  *  Nordic NRF52840
  *  RP2040 Pico and RP2040 Pico W
* To run `rs-matter` on top of the [ESP-IDF](https://github.com/esp-rs/esp-idf-svc) with Espressif MCUs, look at [`esp-idf-matter`](https://github.com/ivmarkov/esp-idf-matter)

## Documentation

We'll have an `rs-matter` Rust Book in future, but in the meantime - look at the [examples](examples), [docs](docs), as well as the code documentation.
Use the [discussions](https://github.com/project-chip/rs-matter/discussions) to ask questions.

## Status Quo

`rs-matter` is still in development, and APIs are likely to see backwards-incompatible changes still, though the blast radius should be more limited now.

With that said, provisioning and operating under the major Smart Home controllers, that is:
- Google Home
- Apple HomeKit
- Alexa
- Home Assistant

... does work without issues.

## Next steps

* Enable more ConnectedHomeIP YAML tests;
* More intelligent reporting on subscriptions;
* Support for Events.

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

### `devenv.nix`

This is used for normal development of applications.
To enter this shell, run `devenv shell` in the project root.
You can optionally follow this with your preferred shell e.g. `devenv shell zsh`.

This requires [devenv](https://devenv.sh/) to be installed on your system.
For nix managed systems, add `pkgs.devenv` to `environment.systemPackages`.

### `shell.nix`

This is for cases where tools expect a standard Linux filesystem layout (FHS).
Use this shell when running `cargo xtask itest` as it sets up `connectedhomeip` which expects a FHS layout.
To enter this shell, run `nix-shell` in the project root.

## How does it look like?

See the [examples](examples).

Note that using the "Matter Stack" metaphor of [`rs-matter-stack`](https://github.com/ivmarkov/rs-matter-stack) / [`rs-matter-embassy`](https://github.com/ivmarkov/rs-matter-embassy) / [`esp-idf-matter`](https://github.com/ivmarkov/esp-idf-matter) results in less bootstrapping boilerplate.

```rust
/*
 *
 *    Copyright (c) 2020-2022 Project CHIP Authors
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

//! An example Matter device that implements a Speaker device over Ethernet.
//! Demonstrates how to make use of the `rs_matter::import` macro for `LevelControl`.

use core::cell::Cell;
use core::pin::pin;

use std::net::UdpSocket;

use embassy_futures::select::select4;
use embassy_sync::blocking_mutex::raw::NoopRawMutex;

use log::info;

use level_control::{
    ClusterAsyncHandler as _, MoveRequest, MoveToClosestFrequencyRequest, MoveToLevelRequest,
    MoveToLevelWithOnOffRequest, MoveWithOnOffRequest, OptionsBitmap, StepRequest,
    StepWithOnOffRequest, StopRequest, StopWithOnOffRequest,
};

use rs_matter::dm::clusters::desc::{self, ClusterHandler as _};
use rs_matter::dm::clusters::net_comm::NetworkType;
use rs_matter::dm::clusters::on_off::{ClusterHandler as _, OnOffHandler};
use rs_matter::dm::devices::test::{TEST_DEV_ATT, TEST_DEV_COMM, TEST_DEV_DET};
use rs_matter::dm::devices::DEV_TYPE_SMART_SPEAKER;
use rs_matter::dm::endpoints;
use rs_matter::dm::networks::unix::UnixNetifs;
use rs_matter::dm::subscriptions::Subscriptions;
use rs_matter::dm::{
    Async, AsyncHandler, AsyncMetadata, Cluster, Dataver, EmptyHandler, Endpoint, EpClMatcher,
    InvokeContext, Node, ReadContext, WriteContext,
};
use rs_matter::error::{Error, ErrorCode};
use rs_matter::pairing::DiscoveryCapabilities;
use rs_matter::persist::Psm;
use rs_matter::respond::DefaultResponder;
use rs_matter::tlv::Nullable;
use rs_matter::transport::MATTER_SOCKET_BIND_ADDR;
use rs_matter::utils::select::Coalesce;
use rs_matter::utils::storage::pooled::PooledBuffers;
use rs_matter::{clusters, devices, with, Matter, MATTER_PORT};

// Import the LevelControl cluster from `rs-matter`.
//
// This will auto-generate all Rust types related to the LevelControl cluster
// in a module named `level_control`.
//
// User needs to implement the `ClusterAsyncHandler` trait or the `ClusterHandler` trait
// so as to handle the requests from the controller.
rs_matter::import!(LevelControl);

#[path = "../common/mdns.rs"]
mod mdns;

fn main() -> Result<(), Error> {
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "info"),
    );

    // Create the Matter object
    let matter = Matter::new_default(&TEST_DEV_DET, TEST_DEV_COMM, &TEST_DEV_ATT, MATTER_PORT);

    // Need to call this once
    matter.initialize_transport_buffers()?;

    // Create the transport buffers
    let buffers = PooledBuffers::<10, NoopRawMutex, _>::new(0);

    // Create the subscriptions
    let subscriptions = Subscriptions::<3>::new();

    // Assemble our Data Model handler by composing the predefined Root Endpoint handler with our custom Speaker handler
    let dm_handler = dm_handler(&matter);

    // Create a default responder capable of handling up to 3 subscriptions
    // All other subscription requests will be turned down with "resource exhausted"
    let responder = DefaultResponder::new(&matter, &buffers, &subscriptions, dm_handler);

    // Run the responder with up to 4 handlers (i.e. 4 exchanges can be handled simultaneously)
    // Clients trying to open more exchanges than the ones currently running will get "I'm busy, please try again later"
    let mut respond = pin!(responder.run::<4, 4>());

    // Create the Matter UDP socket
    let socket = async_io::Async::<UdpSocket>::bind(MATTER_SOCKET_BIND_ADDR)?;

    // Run the Matter and mDNS transports
    let mut mdns = pin!(mdns::run_mdns(&matter));
    let mut transport = pin!(matter.run(&socket, &socket, DiscoveryCapabilities::IP));

    // Create, load and run the persister
    let mut psm: Psm<4096> = Psm::new();

    let dir = std::env::temp_dir().join("rs-matter");

    psm.load(&dir, &matter)?;

    let mut persist = pin!(psm.run(dir, &matter));

    // Combine all async tasks in a single one
    let all = select4(&mut transport, &mut mdns, &mut persist, &mut respond);

    // Run with a simple `block_on`. Any local executor would do.
    futures_lite::future::block_on(all.coalesce())
}

/// The Node meta-data describing our Matter device.
const NODE: Node<'static> = Node {
    id: 0,
    endpoints: &[
        endpoints::root_endpoint(NetworkType::Ethernet),
        Endpoint {
            id: 1,
            device_types: devices!(DEV_TYPE_SMART_SPEAKER),
            clusters: clusters!(
                desc::DescHandler::CLUSTER,
                OnOffHandler::CLUSTER,
                LevelControlHandler::CLUSTER
            ),
        },
    ],
};

/// The Data Model handler + meta-data for our Matter device.
/// The handler is the root endpoint 0 handler plus the Speaker handler.
fn dm_handler(matter: &Matter<'_>) -> impl AsyncMetadata + AsyncHandler + 'static {
    (
        NODE,
        endpoints::with_eth(
            &(),
            &UnixNetifs,
            matter.rand(),
            endpoints::with_sys(
                &false,
                matter.rand(),
                EmptyHandler
                    .chain(
                        EpClMatcher::new(Some(1), Some(desc::DescHandler::CLUSTER.id)),
                        Async(desc::DescHandler::new(Dataver::new_rand(matter.rand())).adapt()),
                    )
                    .chain(
                        EpClMatcher::new(Some(1), Some(LevelControlHandler::CLUSTER.id)),
                        LevelControlHandler::new(Dataver::new_rand(matter.rand())).adapt(),
                    )
                    .chain(
                        EpClMatcher::new(Some(1), Some(OnOffHandler::CLUSTER.id)),
                        Async(OnOffHandler::new(Dataver::new_rand(matter.rand())).adapt()),
                    ),
            ),
        ),
    )
}

/// A sample NOOP handler for the LevelControl cluster.
pub struct LevelControlHandler {
    dataver: Dataver,
    level: Cell<u8>,
}

impl LevelControlHandler {
    /// Create a new instance of the handler
    pub const fn new(dataver: Dataver) -> Self {
        Self {
            dataver,
            level: Cell::new(0),
        }
    }

    /// Adapt the handler instance to the generic `rs-matter` `AsyncHandler` trait
    pub const fn adapt(self) -> level_control::HandlerAsyncAdaptor<Self> {
        level_control::HandlerAsyncAdaptor(self)
    }

    /// Update the volume level of the handler
    fn set_level(&self, state: u8, ctx: &InvokeContext<'_>) {
        let old_state = self.level.replace(state);

        if old_state != state {
            // Update the cluster data version and notify potential subscribers
            self.dataver.changed();
            ctx.notify_changed();
        }
    }
}

impl level_control::ClusterAsyncHandler for LevelControlHandler {
    /// The metadata cluster definition corresponding to the handler
    const CLUSTER: Cluster<'static> = level_control::FULL_CLUSTER
        .with_revision(1)
        .with_attrs(with!(required))
        .with_cmds(with!(
            level_control::CommandId::MoveToLevel
                | level_control::CommandId::Move
                | level_control::CommandId::Step
                | level_control::CommandId::Stop
                | level_control::CommandId::MoveToLevelWithOnOff
                | level_control::CommandId::MoveWithOnOff
                | level_control::CommandId::StepWithOnOff
                | level_control::CommandId::StopWithOnOff
        ));

    fn dataver(&self) -> u32 {
        self.dataver.get()
    }

    fn dataver_changed(&self) {
        self.dataver.changed();
    }

    async fn current_level(&self, _ctx: &ReadContext<'_>) -> Result<Nullable<u8>, Error> {
        Ok(Nullable::some(self.level.get()))
    }

    async fn options(&self, _ctx: &ReadContext<'_>) -> Result<OptionsBitmap, Error> {
        Ok(OptionsBitmap::empty())
    }

    async fn set_options(
        &self,
        _ctx: &WriteContext<'_>,
        _value: OptionsBitmap,
    ) -> Result<(), Error> {
        Ok(())
    }

    async fn on_level(&self, _ctx: &ReadContext<'_>) -> Result<Nullable<u8>, Error> {
        Ok(Nullable::none())
    }

    async fn set_on_level(
        &self,
        _ctx: &WriteContext<'_>,
        _value: Nullable<u8>,
    ) -> Result<(), Error> {
        Ok(())
    }

    async fn handle_move_to_level(
        &self,
        ctx: &InvokeContext<'_>,
        request: MoveToLevelRequest<'_>,
    ) -> Result<(), Error> {
        info!("Moving to level: {}", request.level()?);

        self.set_level(request.level()?, ctx);

        Ok(())
    }

    async fn handle_move(
        &self,
        _ctx: &InvokeContext<'_>,
        request: MoveRequest<'_>,
    ) -> Result<(), Error> {
        info!(
            "Moving {:?} with rate: {:?}",
            request.move_mode()?,
            request.rate()?
        );

        Ok(())
    }

    async fn handle_step(
        &self,
        _ctx: &InvokeContext<'_>,
        request: StepRequest<'_>,
    ) -> Result<(), Error> {
        info!(
            "Stepping {:?} with step size: {} and transition time: {:?}",
            request.step_mode()?,
            request.step_size()?,
            request.transition_time()?
        );

        Ok(())
    }

    async fn handle_stop(
        &self,
        _ctx: &InvokeContext<'_>,
        _request: StopRequest<'_>,
    ) -> Result<(), Error> {
        info!("Stopping");

        Ok(())
    }

    async fn handle_move_to_level_with_on_off(
        &self,
        ctx: &InvokeContext<'_>,
        request: MoveToLevelWithOnOffRequest<'_>,
    ) -> Result<(), Error> {
        info!("Moving to level with on/off: {}", request.level()?);

        self.set_level(request.level()?, ctx);

        Ok(())
    }

    async fn handle_move_with_on_off(
        &self,
        _ctx: &InvokeContext<'_>,
        request: MoveWithOnOffRequest<'_>,
    ) -> Result<(), Error> {
        info!(
            "Moving with on/off: {:?} with rate: {:?}",
            request.move_mode()?,
            request.rate()?
        );

        Ok(())
    }

    async fn handle_step_with_on_off(
        &self,
        _ctx: &InvokeContext<'_>,
        request: StepWithOnOffRequest<'_>,
    ) -> Result<(), Error> {
        info!(
            "Stepping with on/off: {:?} with step size: {} and transition time: {:?}",
            request.step_mode()?,
            request.step_size()?,
            request.transition_time()?
        );

        Ok(())
    }

    async fn handle_stop_with_on_off(
        &self,
        _ctx: &InvokeContext<'_>,
        _request: StopWithOnOffRequest<'_>,
    ) -> Result<(), Error> {
        info!("Stopping with on/off");

        Ok(())
    }

    async fn handle_move_to_closest_frequency(
        &self,
        _ctx: &InvokeContext<'_>,
        _request: MoveToClosestFrequencyRequest<'_>,
    ) -> Result<(), Error> {
        Err(ErrorCode::InvalidAction.into())
    }
}
```

## Build

### Building the library and all examples

```sh
$ cargo build --features zeroconf
```

#### **NOTE**: mDNS issues (e.g. "running the example fails with strange error messages mentioning mDNS").

These days mDNS is still a PITA especially on Linux, but not only.

`rs-matter` currently offers no less than 5 (five!) mDNS implementations (three well-supported ones - `avahi`, `resolve` and `builtin` -
for production use-cases on embedded MCUs and embedded Linux, as well as two legacy ones - `zeroconf` and `astro-dnssd` - which are kept around
for compatibility with Windows and MacOSX; look inside `rs-matter/rs-matter/src/transport/network/mdns` for more details on those).

The TL;DR is, rather than building with `--features zeroconf` everywhere, you can try:
- On Linux, all of the above, but `--features avahi` and `--features zeroconf` are your best bet;
- On MacOSX, `--features astro-dnssd` is known to work fine;
- On Windows, try `--features astro-dnssd` or `--features zeroconf`.

### Unit Tests
```sh
$ cargo test -- --test-threads 1
```

## Test

With the [`chip-tool` (the current tool for testing Matter)](https://github.com/project-chip/connectedhomeip/blob/master/examples/chip-tool/README.md) use the Ethernet commissioning mechanism:

```sh
$ chip-tool pairing code 12344321 <Pairing-Code>
```

Or alternatively:

```sh
$ chip-tool pairing ethernet 12344321 123456 0 <IP-Address> 5540
```

Interact with the device

```sh
# Read server-list
$ chip-tool descriptor read server-list 12344321 0

# Read On/Off status
$ chip-tool onoff read on-off 12344321 1

# Toggle On/Off by invoking the command
$ chip-tool onoff on 12344321 1
```

# Test with Google/Apple/Alexa controllers

All of these should work. Follow the instructions in your controller phone app.
