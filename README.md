# ![alt text](https://avatars.githubusercontent.com/u/61027988?s=48&v=4 "rs-matter") rs-matter

[![license](https://img.shields.io/badge/license-Apache2-green.svg)](https://raw.githubusercontent.com/project-chip/rs-matter/main/LICENSE)
[![CI](https://github.com/project-chip/rs-matter/actions/workflows/ci.yml/badge.svg)](https://github.com/project-chip/rs-matter/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/rs-matter.svg)](https://crates.io/crates/rs-matter)
[![Matrix](https://img.shields.io/matrix/rs-matter:matrix.org?label=join%20matrix&color=BEC5C9&logo=matrix)](https://matrix.to/#/#rs-matter:matrix.org)

## What is it exactly?

**A pure-Rust, `no_std`, no-alloc, async-first, extensible and safe implementation of the [Matter protocol](https://csa-iot.org/all-solutions/matter/)**.

Scales from bare-metal MCUs with 1MB flash and 256KB RAM to ARM embedded Linux and bigger iron!

## Crates

`rs-matter` is the crate to depend on. It re-exports the following crates, which hold the implementation,
under a single set of paths and features:

| Crate | Contents |
|---|---|
| `rs-matter-utils` | The error type, synchronization primitives, storage, timers, futures, I/O, in-place initialization |
| `rs-matter-tlv` | The TLV encoding, and the `FromTLV` / `ToTLV` traits |
| `rs-matter-crypto` | The crypto traits and backends, the group key derivation |
| `rs-matter-cert` | Operational certificates and device attestation |
| `rs-matter-pairing` | The manual pairing code, the QR code and the NFC payload |
| `rs-matter-im-core` | The Interaction Model encoding |
| `rs-matter-dm-core` | The Data Model types: metadata, handler traits, persistence traits |
| `rs-matter-dm-clusters` | The cluster types, handler traits and clients generated from the Matter IDL |
| `rs-matter-node-core` | What the node is built on: the fabrics, the ACL, the fail-safe, the basic information settings |
| `rs-matter-transport` | The transport (exchanges, sessions, MRP, UDP, TCP, BTP, mDNS), the IM client |
| `rs-matter-sc` | The Secure Channel protocol: PASE, CASE, Check-In |
| `rs-matter-node` | `Matter`, which puts the transport, the Secure Channel state and the state of the node together |
| `rs-matter-bdx` | The Bulk Data Exchange protocol |
| `rs-matter-im` | The Interaction Model engine |
| `rs-matter-dm` | The cluster handlers and the root endpoint |
| `rs-matter-respond` | The responders of the incoming exchanges |
| `rs-matter-onboard` | The commissioner |
| `rs-matter-stack` | The assembly of the node over a network driver |

The split keeps the large generated code in a crate of its own, so that changes to the other crates are
type-checked quickly. See [docs/crate-split-design.md](docs/crate-split-design.md) for the details.

## I just want to run Matter on my MCU!

* To run `rs-matter` on baremetal MCUs with [Embassy](https://github.com/embassy-rs/embassy), look at [`rs-matter-embassy`](https://github.com/sysgrok/rs-matter-embassy). Currently supported MCUs:
  *  Espressif ESP32XX
  *  Nordic NRF52840
  *  RP2040 Pico and RP2040 Pico W
* To run `rs-matter` on top of the [ESP-IDF](https://github.com/esp-rs/esp-idf-svc) with Espressif MCUs, look at [`esp-idf-matter`](https://github.com/sysgrok/esp-idf-matter)
* To run `rs-matter` on top of any other vendor SDK which is not supported out of the box, you'll have to implement the `rs-matter` platform traits, as [`rs-matter-embassy`](https://github.com/sysgrok/rs-matter-embassy) and [`esp-idf-matter`](https://github.com/sysgrok/esp-idf-matter) do.

## Documentation

We'll have an `rs-matter` Rust Book in future, but in the meantime - look at the [examples](examples), [docs](docs), as well as the code documentation.
Use the [discussions](https://github.com/project-chip/rs-matter/discussions) to ask questions.

## Status Quo

`rs-matter` is *relatively feature complete*, and can be used to implement both accessories (the typical use case),
as well as controllers and commissioners.

With that said, the API is not stable and is likely to still see some backwards-incompatible changes,
though the blast radius should be more limited now.

The currently supported Matter Specification version is **1.6**.

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

`rs-matter` ships a `flake.nix` providing two reproducible environments. Both pin `nixpkgs` and the
Rust toolchain, so every machine and CI run gets the same versions. Requires nix with flakes enabled.

#### Normal development

```sh
nix develop          # or `nix develop -c zsh` for your preferred shell
```

#### Running `cargo xtask itest`

The integration tests set up `connectedhomeip`, which expects a standard Linux filesystem layout
(FHS). The `fhs` output provides one:

```sh
nix run .#fhs                             # interactive shell, then run cargo xtask itest
nix run .#fhs -- -c 'cargo xtask itest'   # one-shot
```

#### Updating

`flake.lock` pins `nixpkgs`; update it with `nix flake update`. The Rust version is set
explicitly at the top of `flake.nix` - edit `rustVersion` there. Commit the result either way.

## How does it look like?

See the [examples](examples). This is [`onoff_light`](examples/src/bin/onoff_light.rs), an On/Off Light over Ethernet:

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

//! An example Matter device that implements the On/Off Light cluster over Ethernet.
//!
//! Endpoint 1 also carries a `ModeSelect` instance as an *extra* cluster - the
//! endpoint keeps On/Off Light as its single Application device type, since
//! Core spec 9.2.1 allows only one per Simple endpoint and Mode Select
//! (`0x0027`) is itself an application type. This mirrors CHIP's
//! `all-clusters-app`, which likewise carries ModeSelect on its On/Off Light
//! endpoint without declaring the Mode Select device type. It demonstrates the generic
//! "pick one of N vendor-defined options" cluster: it chooses the light's
//! pattern. Because the same endpoint hosts On/Off, it also demonstrates the
//! `ON_OFF` (`DEPONOFF`) feature - switching the light on snaps the pattern
//! back to `OnMode`, its power-on default.

use core::pin::pin;

use log::info;

use rand::rngs::StdRng;

use rand::Rng;

use rs_matter::crypto::{default_crypto, Crypto};
use rs_matter::dm::clusters::app::level_control::LevelControlHooks;
use rs_matter::dm::clusters::app::on_off::{
    self, test::TestOnOffDeviceLogic, NoLevelControl, OnOffHooks,
};
use rs_matter::dm::clusters::desc::{self, ClusterHandler as _};
use rs_matter::dm::clusters::groups::{self, ClusterHandler as _};
use rs_matter::dm::clusters::mode_select::{
    self, Mode, ModeId, ModeSelectHandler, ModeSelectHooks, SemanticTag,
};
use rs_matter::dm::devices::test::{DAC_PRIVKEY, TEST_DEV_ATT, TEST_DEV_COMM, TEST_DEV_DET};
use rs_matter::dm::devices::DEV_TYPE_ON_OFF_LIGHT;
use rs_matter::dm::endpoints::ROOT_ENDPOINT_ID;
use rs_matter::dm::networks::SysNetifs;
use rs_matter::dm::{Async, Cluster, DataModel, Dataver, EmptyHandler, Endpoint, Node};
use rs_matter::error::Error;
use rs_matter::persist::DirKvBlobStore;
use rs_matter::tlv::Nullable;
use rs_matter::utils::cell::RefCell;
use rs_matter::utils::sync::blocking::Mutex;
use rs_matter::{clusters, devices, root_endpoint, with, Matter};

use rs_matter::dm::networks::eth::EthNetwork;
use rs_matter::stack::eth::PreexistingEthernet;
use rs_matter::stack::net::std::StdNetStack;
use rs_matter::stack::MatterStack;
use rs_matter::utils::init::InitMaybeUninit;

use static_cell::StaticCell;

#[path = "../common/mdns.rs"]
mod mdns;

/// The vendor ID whose namespace our semantic tags live in. `TEST_DEV_DET`
/// commissions as vendor `0xFFF1` (the CSA test vendor).
const TEST_VENDOR: u16 = 0xFFF1;

/// Our own semantic tag values. Manufacturer specific tags live in
/// `0x8000..=0xBFFF`; within that range the meaning is ours to define.
const TAG_STEADY: u16 = 0x8000;
const TAG_BLINK: u16 = 0x8001;
const TAG_PULSE: u16 = 0x8002;

/// The light patterns this device can be set to.
///
/// `ModeSelect` has no standard vocabulary for "light pattern", which is
/// exactly when it is the right cluster to reach for: the purpose is carried
/// by the `Description` string and the tags are ours. A Mode Base derived
/// cluster would need a cluster ID the spec does not define for this.
///
/// Mode `4` is deliberately present because CHIP's `Test_TC_MOD_2_1` defaults
/// its `NewMode` argument to 4.
const LIGHT_PATTERNS: &[Mode] = &[
    Mode::new(0, "Steady", &[SemanticTag::new(TEST_VENDOR, TAG_STEADY)]),
    Mode::new(4, "Blink", &[SemanticTag::new(TEST_VENDOR, TAG_BLINK)]),
    Mode::new(7, "Pulse", &[SemanticTag::new(TEST_VENDOR, TAG_PULSE)]),
];

/// Device logic behind the `ModeSelect` instance on endpoint 1.
///
/// The handler owns and persists `CurrentMode`, `StartUpMode` and `OnMode`;
/// this logic would drive the LED from `change_to_mode`, and just logs.
struct LightPatternLogic {
    state: Mutex<RefCell<LightPatternState>>,
}

struct LightPatternState {
    current: ModeId,
}

impl LightPatternLogic {
    const fn new() -> Self {
        Self {
            state: Mutex::new(RefCell::new(LightPatternState { current: 0 })),
        }
    }
}

impl ModeSelectHooks for LightPatternLogic {
    // `StartUpMode` and `OnMode` are optional, and `OnMode` is what the
    // `ON_OFF` feature adds - so both must be opted into explicitly.
    const CLUSTER: Cluster<'static> = mode_select::FULL_CLUSTER
        .with_features(mode_select::Feature::ON_OFF.bits())
        .with_attrs(with!(
            required;
            mode_select::AttributeId::StartUpMode | mode_select::AttributeId::OnMode
        ));

    // Come up blinking after a power cycle...
    const START_UP_MODE: Option<ModeId> = Some(4);

    // ...but snap to steady whenever the light is switched on.
    const ON_MODE: Option<ModeId> = Some(0);

    fn description(&self) -> &str {
        "Light pattern"
    }

    // Null: our tags are all manufacturer specific, so there is no standard
    // namespace to point at.
    fn standard_namespace(&self) -> Nullable<u16> {
        Nullable::none()
    }

    fn supported_modes(&self) -> &[Mode<'_>] {
        LIGHT_PATTERNS
    }

    fn change_to_mode(&self, mode: ModeId) -> Result<(), Error> {
        info!("Light pattern -> {mode}");

        // A real device drives its LED here; the handler owns and persists
        // `CurrentMode`.
        self.state.lock(|s| s.borrow_mut().current = mode);

        Ok(())
    }
}

/// The bump allocator size of the stack, in bytes.
///
/// If it is not enough, the stack panics while it starts. The futures of an
/// unoptimized build are much bigger than those of an optimized one.
const BUMP_SIZE: usize = 32 * 1024;

/// The stack is allocated statically to avoid program stack blowups.
static MATTER_STACK: StaticCell<MatterStack<BUMP_SIZE, EthNetwork>> = StaticCell::new();

fn main() -> Result<(), Error> {
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "info"),
    );

    let stack = MATTER_STACK.uninit().init_with(MatterStack::init(
        &TEST_DEV_DET,
        TEST_DEV_COMM,
        &TEST_DEV_ATT,
    ));

    // Persistence
    let mut store = DirKvBlobStore::new_default();

    // Create the crypto instance
    // `rand::rng()` is not `Send`
    let crypto = default_crypto(rand::make_rng::<StdRng>(), DAC_PRIVKEY);

    let mut rand = crypto.rand()?;

    // Re-hydrate the persisted state. If the device is not commissioned yet, this also
    // prints the QR text and code to the console and enables basic commissioning.
    futures_lite::future::block_on(stack.startup(&crypto, &mut store))?;

    // Bind the KV access object (the KV scratch buffer lives in `Matter`).
    let kv = stack.kv(store);

    // Our mode-select cluster, choosing the light's pattern
    let mode_select_handler = ModeSelectHandler::new(
        Dataver::new_rand(&mut rand),
        rs_matter::persist::VENDOR_KEYS_START + 0x11,
        LightPatternLogic::new(),
    );

    // Our on-off cluster, coupled to the mode-select one so that switching the
    // light on applies `OnMode` (the ModeSelect `ON_OFF` feature). This is the
    // long form of `new_standalone`, so the coupling can be attached before
    // `init`.
    let on_off_handler = on_off::OnOffHandler::<_, NoLevelControl>::new(
        Dataver::new_rand(&mut rand),
        1,
        rs_matter::persist::VENDOR_KEYS_START + 0x10,
        TestOnOffDeviceLogic::new(true),
    )
    .with_on_mode_applier(&mode_select_handler);

    on_off_handler.init(None);

    // Run the stack, which adds the operational network clusters of endpoint 0 by itself
    let matter = pin!(stack.run_eth(
        PreexistingEthernet::new(
            // The UDP sockets of the node
            StdNetStack::new(),
            // The network interfaces of the host
            SysNetifs,
            // No Ethernet diagnostics to report
            &(),
            mdns::create_mdns(),
        ),
        &crypto,
        data_model(stack.matter(), rand, &on_off_handler, &mode_select_handler),
        kv,
        // No user task to run
        (),
    ));

    // Run with a simple `block_on`. Any local executor would do.
    futures_lite::future::block_on(matter)
}

/// The Node meta-data describing our Matter device.
const NODE: Node<'static> = Node {
    endpoints: &[
        root_endpoint!(eth),
        Endpoint::new(
            1,
            devices!(DEV_TYPE_ON_OFF_LIGHT),
            clusters!(
                desc::DescHandler::CLUSTER,
                groups::GroupsHandler::CLUSTER,
                TestOnOffDeviceLogic::CLUSTER,
                LightPatternLogic::CLUSTER
            ),
        ),
    ],
};

/// The Data Model handler + meta-data for our Matter device.
/// The handler is the root endpoint 0 handler plus the on-off handler and its descriptor.
fn data_model<'a, OH: OnOffHooks, LH: LevelControlHooks, MH: ModeSelectHooks>(
    matter: &'a Matter<'a>,
    mut rand: impl Rng + Copy,
    on_off: &'a on_off::OnOffHandler<'a, OH, LH>,
    mode_select: &'a ModeSelectHandler<MH>,
) -> impl DataModel + 'a {
    (
        NODE,
        EmptyHandler
            .chain(
                |e, _| e == ROOT_ENDPOINT_ID,
                Async(MatterStack::<0, EthNetwork>::root_handler(
                    matter,
                    &(),
                    rand,
                )),
            )
            .chain(
                |e, c| e == 1 && c == desc::DescHandler::CLUSTER.id,
                Async(desc::DescHandler::new(Dataver::new_rand(&mut rand)).adapt()),
            )
            .chain(
                |e, c| e == 1 && c == groups::GroupsHandler::CLUSTER.id,
                Async(groups::GroupsHandler::new(Dataver::new_rand(&mut rand), matter).adapt()),
            )
            .chain(
                |e, c| e == 1 && c == TestOnOffDeviceLogic::CLUSTER.id,
                Async(on_off::HandlerAdaptor(on_off)),
            )
            .chain(
                |e, c| e == 1 && c == LightPatternLogic::CLUSTER.id,
                Async(mode_select::HandlerAdaptor(mode_select)),
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
for compatibility with Windows and MacOSX; look inside `rs-matter-transport/src/network/mdns` for more details on those.

The TL;DR is, rather than building with `--features zeroconf` everywhere, you can try:
- On Linux: all of the above, but `--features avahi` and `--features resolve` are your best bet in production;
- On MacOSX: `--features astro-dnssd` is known to work fine;
- On Windows: try the built-in mDNS resolver.

### Flash size on embedded targets (`rustcrypto` backend)

The RustCrypto `sha2` and `aes` crates select their software backend with a `--cfg` flag rather than with a Cargo feature,
and the default is the *unrolled* (faster, ~5KB larger) SHA-256.On flash-constrained MCUs, put in your `.cargo/config.toml`:

```toml
[build]
rustflags = ["--cfg", "sha2_backend_soft=\"compact\"", "--cfg", "aes_backend_soft=\"compact\""]
```

This is what the `bloat-check` project (the CI flash-size gate) does.

### Unit tests and internal E2E tests
```sh
cargo test -- --test-threads 1
```

### E2E/acceptance tests from the C++ SDK
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
