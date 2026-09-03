# matter-fast — Rust Matter server with matterjs-server (Home Assistant) parity

Goal: a single Rust binary on Linux (Raspberry Pi, podman, port 5580) that Home
Assistant's Matter integration connects to over WebSocket exactly like it
connects to `matterjs-server` / `python-matter-server`, and that can commission
and control a real lamp. Built on the official project-chip `rs-matter` stack.

This file is the work plan for Sonnet/Opus subagents. Each task says which
model tier to use, what to read, what to produce, and how it is verified.
Do not skip the verification step; do not widen a task's scope.

## 0. Decisions already made (do not re-litigate)

1. **Protocol layer is written once, backend-agnostic.** All HA wire-format
   code (commands, events, error codes, path strings, JSON value model) lives
   in `server/crates/ws-protocol` and never touches a Matter stack directly.
   Backends implement one `Backend` trait (§3).
2. **Two backends, one at a time.**
   - `backend-mc` (`matter-controller` 0.11 from crates.io, third-party) — the
     *fast path*. The existing prototype in `../matter-rs/` already runs on it;
     it gets ported into this workspace and its protocol bugs fixed. This is
     what puts the lamp into HA first.
   - `backend-rsm` (`rs-matter`, path dep on `./rs-matter`, official) — the
     *target*. Replaces `backend-mc` when it passes the same conformance suite.
   The user picks the backend with `--backend mc|rsm`; default is whichever
   passes the conformance suite (mc until rsm does).
3. **Milestone 1 uses on-network commissioning only.** HA's companion app
   commissions the lamp with the phone, opens a commissioning window, and the
   server commissions over IP with the pairing code (`network_only`). No BLE,
   no Wi-Fi/Thread provisioning until §6.
4. **Conformance oracle = the real clients.** `matterjs-server/python_client`
   (the python-matter-server client, what HA uses) and
   `matterjs-server/packages/ws-client` are the spec. If the docs and the
   TypeScript disagree, the TypeScript wins.
5. **Attestation:** accept device attestation unconditionally (home use). Both
   stacks support this (`allow_test_attestation: true` /
   `AttestationTrust::example_device_roots()`). Real DCL/PAA validation is a
   later, optional task.
6. **No dashboard.** HA is the UI. `GET /health` and `/ws` only (plus
   `POST /ota-upload/<id>` in §7).

## 1. Repository layout

```
matter-fast/
  PLAN.md                     this file
  docs/WIRE_PROTOCOL.md       exact JSON contracts extracted from the TS source (task T1)
  rs-matter/                  git checkout of project-chip/rs-matter (pin: 3a27068, 2026-09-03)
  matterjs-server/            git checkout of matter-js/matterjs-server v1.4.1-alpha.2 (reference + test client)
  server/                     NEW cargo workspace (everything we write)
    Cargo.toml                [workspace] members = crates/*
    crates/ws-protocol/       wire types, error codes, path parsing, JSON value model, Backend trait
    crates/backend-mc/        matter-controller backend (port of ../../matter-rs/src/app.rs)
    crates/backend-rsm/       rs-matter backend
    crates/matter-server/     bin: CLI, tokio HTTP+WS listener, wiring
    conformance/              python: runs python_client against a live server (task T5)
    Dockerfile                debian:trixie-slim, arm64+amd64
```

Existing prototype to mine: `../matter-rs/` (`src/main.rs` listener + `/health`
routing, `src/app.rs` command dispatch, `src/value.rs` TLV<->JSON,
`tests/ws_smoke.rs`). It compiles today (`cargo build` in `../matter-rs`).

## 2. What HA actually sends and expects (read before touching wire code)

Authoritative, in this order:

1. `matterjs-server/packages/ws-controller/src/server/WebSocketControllerHandler.ts`
2. `matterjs-server/packages/ws-controller/src/controller/ControllerCommandHandler.ts`
3. `matterjs-server/packages/ws-client/src/models/model.ts` (wire types)
4. `matterjs-server/python_client/matter_server/common/models.py` (`APICommand`,
   `MatterNodeData`, `ServerInfoMessage`, `ErrorResultMessage`, `EventType`)
5. `matterjs-server/docs/websockets_api.md` (prose; may lag the code)

**The exact contract is in `docs/WIRE_PROTOCOL.md`** (extracted from the TS
source with `file:line` citations, 2026-09-03). Read it in full before touching
wire code. The points the current `../matter-rs` prototype gets wrong:

- Errors are `{"message_id", "error_code": <int>, "details": <string>}`,
  not `{"error": ...}`. Unknown command (and `subscribe_attribute`) → code 9.
- Every event is `{"event": "<name>", "data": <payload>}`.
  `attribute_updated` data is `[node_id, "endpoint/cluster/attribute", value]`;
  `node_removed` data is the bare node id; `node_added`/`node_updated` data is
  the full node object (`date_commissioned`, `last_interview`,
  `interview_version: 6`, `available`, `is_bridge`, `attributes`,
  `attribute_subscriptions: []`, `matter_version?`).
- The server pushes a bare `server_info` object immediately on connect.
  `server_info` includes OHF-only `fabric_index`, `ble_proxy_enabled`,
  `controller_node_id`, and `wifi_ssid` (only when set).
- Attribute paths are strings `"<endpoint>/<cluster>/<attribute>"`, decimal,
  any non-numeric token is a wildcard. `read_attribute` takes a string or
  array and returns a **flat object** `{"1/6/0": true}`. `write_attribute`
  returns `[{"Path": {"EndpointId", "ClusterId", "AttributeId"}, "Status"}]`
  (PascalCase — the only such shape).
- **Attribute values are tag-based**: structs are objects keyed by the
  numeric TLV context tag as a string (`{"0": 1, "1": "x"}`), lists are
  arrays, 64-bit integers are bare JSON numbers. This is what
  `../matter-rs/src/value.rs` already does, minus the `{"$bytes"}` wrapper —
  check `Converters.ts:346-463` for the octet-string / nullable / bitmap
  encoding and match it exactly. **Verified in T3 (2026-09-03): octet strings
  are base64, not hex** (`Bytes.toBase64`/`fromBase64`, `Converters.ts:264`
  and `@matter/general` `Bytes.ts:52,115`); enums and bitmaps are plain
  integers; `epoch_s`/`epoch_us` need no offset (matter.js's TLV codec adds the
  Matter epoch on decode and `Converters.ts` subtracts it again, so the wire
  value equals the raw TLV value).
- **Names are used in exactly three places**: `device_command.command_name`
  (camelCase, matched by name), `device_command.payload` + its response
  (fields by camelCase name), and `node_event.data` (fields by name). That is
  the whole scope of the IDL name table (task T3).
- `commission_on_network` args are `setup_pin_code`, `filter_type`, `filter`,
  `ip_addr` — not `code`. `open_commissioning_window` returns
  `setup_pin_code` / `setup_manual_code` / `setup_qr_code`.
- `set_loglevel`/`get_loglevel` use `console_loglevel`/`file_loglevel`.
- Credentials are named lists: `id` arg, reserved `"default"` (and
  `"delete"`), `get_all_credentials` returns summaries only, secrets are
  write-only, every change broadcasts `server_info_updated`.
- `set_default_fabric_label` returns `null`, is a silent no-op when pinned by
  CLI or owned by another live connection.
- `set_acl_entry`/`set_node_binding` return lowercase
  `[{"path": {"endpoint_id", "cluster_id", "attribute_id"}, "status"}]`;
  `fabric_index` is never client-supplied.
- `ping_node` returns `{"<ip>": bool}`; `get_node_ip_addresses` returns
  `string[]`; `get_matter_fabrics` includes `vendor_name`.

## 3. The `Backend` trait (ws-protocol crate)

Keep it small and value-oriented. The protocol crate owns all JSON; backends
speak in these Rust types.

```rust
pub struct AttrPath { pub endpoint: Option<u16>, pub cluster: Option<u32>, pub attribute: Option<u32> } // None = wildcard
pub struct ConcretePath { pub endpoint: u16, pub cluster: u32, pub attribute: u32 }

/// Backend-neutral decoded Matter value (TLV shape, tags preserved).
pub enum MValue { Null, Bool(bool), U(u64), I(i64), F32(f32), F64(f64), Str(String), Bytes(Vec<u8>),
                  Array(Vec<MValue>), Struct(Vec<(u8 /*ctx tag*/, MValue)>) }

pub struct NodeIdentity { pub node_id: u64, pub fabric_id: u64, pub fabric_index: u8 }

pub enum BackendEvent {
    AttributeChanged { node_id: u64, path: ConcretePath, value: MValue },
    Event { node_id: u64, endpoint: u16, cluster: u32, event: u32, event_number: u64, priority: u8, timestamp_ms: Option<u64>, data: MValue },
    NodeAvailability { node_id: u64, available: bool },
    SubscriptionLost { node_id: u64 },
}

#[async_trait]
pub trait Backend: Send + Sync {
    async fn fabric_info(&self) -> FabricSummary;                    // fabric_id, compressed_fabric_id, controller node id
    async fn nodes(&self) -> Vec<NodeIdentity>;
    async fn commission_with_code(&self, code: &str, network_only: bool) -> Result<NodeIdentity, BErr>;
    async fn commission_on_network(&self, pin: u32, filter: DiscoveryFilter, ip: Option<IpAddr>) -> Result<NodeIdentity, BErr>;
    async fn read(&self, node: u64, paths: &[AttrPath]) -> Result<Vec<(ConcretePath, MValue)>, BErr>;
    async fn write(&self, node: u64, path: ConcretePath, value: MValue, timed_ms: Option<u16>) -> Result<Vec<(ConcretePath, u8 /*IM status*/)>, BErr>;
    async fn invoke(&self, node: u64, endpoint: u16, cluster: u32, command: u32, fields: MValue, timed_ms: Option<u16>) -> Result<InvokeOutcome, BErr>;
    async fn subscribe_all(&self, node: u64) -> Result<(), BErr>;       // whole node, attrs + events; backend keeps it alive
    async fn unsubscribe(&self, node: u64);
    async fn remove_node(&self, node: u64) -> Result<(), BErr>;         // RemoveFabric on device + forget locally
    async fn open_commissioning_window(&self, node: u64, timeout_s: u16, discriminator: Option<u16>) -> Result<WindowCodes, BErr>;
    async fn device_fabrics(&self, node: u64) -> Result<Vec<DeviceFabric>, BErr>;
    async fn remove_device_fabric(&self, node: u64, fabric_index: u8) -> Result<(), BErr>;
    async fn update_fabric_label(&self, node: u64, label: &str) -> Result<(), BErr>;
    async fn set_acl(&self, node: u64, entries: Vec<AclEntry>) -> Result<(), BErr>;
    async fn set_bindings(&self, node: u64, endpoint: u16, targets: Vec<BindingTarget>) -> Result<(), BErr>;
    async fn node_addresses(&self, node: u64, prefer_cache: bool) -> Result<Vec<IpAddr>, BErr>;
    async fn discover_commissionable(&self, timeout: Duration) -> Vec<CommissionableNode>;
    async fn icd_register(&self, node: u64) -> Result<IcdState, BErr>;
    async fn icd_unregister(&self, node: u64, force: bool) -> Result<IcdState, BErr>;
    async fn icd_state(&self, node: u64) -> Result<IcdState, BErr>;
    fn events(&self) -> broadcast::Receiver<BackendEvent>;
}
```

Everything HA-shaped (interview cache, `date_commissioned`, `last_interview`,
`is_bridge` detection via Descriptor/PartsList on ep0 + Aggregator device type
`0x000e`, `available`, the `attributes` map, named-value encoding, credential
store, fabric label ownership, event fan-out per connection, `start_listening`
gating, `thread_*`/`network_topology` opt-in per connection) lives in
`ws-protocol::server` and is shared by both backends.

## 4. Milestone 1 — lamp in HA on `backend-mc` (fast path)

Order matters; each task ends with `cargo test --workspace` green.

### T1 — Extract the exact wire contract  [DONE 2026-09-03]
`docs/WIRE_PROTOCOL.md`. One open item for whoever does T2: read
`Converters.ts:346-463` and document in that file how tag-based conversion
encodes octet strings, nullable, enums/bitmaps, floats, and `bigint` fields
(the extraction did not quote that block).

### T2 — Workspace + ws-protocol crate  [Sonnet]
Create `server/` workspace. Move the listener from `../matter-rs/src/main.rs`
into `crates/matter-server` (keep the head-peeking `/health` vs `/ws` routing;
add `POST /ota-upload/<id>` as a 501 stub for now). Create `ws-protocol` with:
`Request`/`Response`/`ErrorResponse{error_code,details}`/`Event{event,data}`,
`ErrorCode` enum with the numeric table, `AttrPath::parse("1/6/*")` /
`Display`, `MValue`, the `Backend` trait, a `MockBackend`, and the shared
`Server` that implements every command in `APICommand` against the trait
(unknown command → `error_code: 9`). Port `../matter-rs/src/value.rs` to
`MValue` <-> JSON with `{"$bytes"}` removed in favour of hex strings per T1.
Verify: unit tests for path parsing, error shapes, event envelopes; a WS
smoke test against `MockBackend` that checks the on-connect `server_info`
push and one `attribute_updated` event shape.

### T3 — Matter IDL name table (commands + events only)  [Opus]  [DONE 2026-09-03]
Correction to the plan below, found while building it: `rs-matter-codegen`
declares `mod idl;` **privately** in `lib.rs`, so `rs_matter_codegen::idl::parser`
is not reachable and its only public entry point is `generate()` against the
pinned 1.6.0.0 IDL. `matter-names` therefore carries its own ~500-line IDL
parser in `src/codegen.rs`, shared by `xtask gen-names` and the drift test.

Attribute values never need names (they are tag-based, §2), so the table is
small. Lives in its own crate `crates/matter-names` (so T2 and T3 can run in
parallel; `ws-protocol` depends on it). Generate `crates/matter-names/src/generated.rs` from
`rs-matter/rs-matter-codegen/src/idl/parser/controller-clusters-V1.5.1.0.matter`
using `rs-matter-codegen`'s parser (`rs_matter_codegen::idl::parser`) via a
checked-in `xtask gen-names` (commit the output; add a test that regeneration
is a no-op). Per cluster id: command name (camelCase) → command id, request
field list (ctx tag, camelCase name, type kind: scalar/enum/bitmap/string/
octstr/struct/list-of/nullable) and the response command's field list; event
id → name + field list; struct definitions used by those fields. Implement
`camelize()` matching matter.js (`"MoveToLevel"`, `"move_to_level"` →
`"moveToLevel"`), `names::encode_command(cluster, name, payload_json) ->
(command_id, MValue)`, `names::decode_response(cluster, name, &MValue) ->
serde_json::Value`, `names::decode_event(cluster, event_id, &MValue) ->
serde_json::Value`. Unknown cluster/command → error 8; unknown event data →
tag-based fallback. Verify: `moveToLevelWithOnOff {level, transitionTime,
optionsMask, optionsOverride}` → cluster 8 cmd 4 with ctx tags 0..3;
`Switch.MultiPressComplete` decodes to `{"previousPosition", "totalNumberOfPressesCounted"}`;
`DoorLock.lockDoor {pinCode}` encodes an octet string.

### T4 — backend-mc  [Sonnet]  [DONE 2026-09-03]
Corrections found while building it, per §8 ("trust the compiler, update this
file"):
- `compressed_fabric_id` (Matter Core Spec §4.3.2.2) is **not** obtainable
  from `matter-controller` 0.11's public API before at least one device is
  reachable: the RCAC root key is minted and kept fully internal
  (`crate::fabric::create_fabric`), `MatterController::fabrics()` returns
  `FabricInfo` with no key material, and `ControllerState`/`FabricEntry`
  (which do carry `rcac_cert`) are reachable only from inside the crate's own
  actor task — not via `ControllerState` as this file assumed. The only
  public path is `Node::list_fabrics()` on an already-commissioned, reachable
  device. `backend-mc/src/fabric_identity.rs` works around this: mint a
  throwaway keypair at boot to derive a *synthetic* but stable/non-zero id
  (satisfies `server_info` before any commissioning), then best-effort
  upgrade to the real, device-derived value the first time any node answers
  `list_fabrics()`, permanently cached from then on.
- `OpenWindowOpts` (and most other request-option structs in this crate) is
  `#[non_exhaustive]`: it cannot be built with a struct literal — not even
  `Foo { a, b, ..Default::default() }` — from outside the crate. Build via
  `Default::default()` then assign fields individually.
- The `IcdManagement` `OperatingMode` attribute id is **8**, not `0x0006` as
  this file's T4 draft guessed — see `crates/matter-names/src/generated.rs`'s
  `Cluster{id:70,...}` entry, the checked-in source of truth.
- The 11-digit manual pairing code (Matter Core Spec §5.1.4, Verhoeff check
  digit included) does not need reimplementing: `matter_commissioning`
  (a direct, already-pinned transitive dependency of `matter-controller`) is
  itself a normal crates.io dependency and publicly re-exports
  `encode_manual_code`/`Discriminator`/`Passcode`/`SetupPayload` at its crate
  root, the exact function `matter-controller`'s own
  `Node::open_commissioning_window` uses. `backend-mc/src/manual_code.rs`
  delegates to it rather than re-deriving Verhoeff independently.

Port `../matter-rs/src/app.rs` onto the `Backend` trait using
`matter-controller` 0.11. The crate already exposes everything needed
(verified in `~/.cargo/registry/src/*/matter-controller-0.11.0/src/`):
`MatterController::{commission, nodes, fabrics, forget_node, node}`,
`Node::{read, write, write_timed, invoke, invoke_timed, subscribe(attrs,
events, min, max), read_acl, write_acl, read_binding, write_binding,
list_fabrics, remove_fabric, update_fabric_label, register_icd_client,
unregister_icd_client, open_commissioning_window, commissioning_window_status}`,
`SubscriptionEvent::{Report, Event, Established, Resubscribing, Lagged}`,
`AclEntry::new`, `BindingTarget::new`, `ReadPath::new(Option,Option,Option)`.
Subscribe with attrs `[ReadPath::all()]` and events `[EventPath::default()]`
(all events) so `node_event` works. `remove_node` must invoke
`RemoveFabric` on the device (`Node::remove_fabric(our index from
list_fabrics)`) before `forget_node`. `commission_on_network` with
`filter_type` 2 (long discriminator) + `setup_pin_code`: build the manual
pairing code from pin + discriminator and call `commission()`; with `ip_addr`
present, pass it through if the crate allows, else document the gap.
Verify: `cargo test`; then the conformance suite (T5) against a real lamp.

### T5 — Conformance harness  [Sonnet]
`server/conformance/`: a `uv` project that installs
`../matterjs-server/python_client` and runs pytest against a running server
(`MATTER_SERVER_URL`). Tests: connect and receive `server_info`;
`start_listening`; `get_nodes`; error shape for unknown node (`error_code 5`)
and unknown command (`9`); `set_wifi_credentials` + `get_all_credentials`
(no secret leaked); `set_default_fabric_label`/`get_fabric_label`. Gated
"live" tests (env `LAMP_CODE`): `commission_with_code`, node object shape,
`read_attribute "1/6/0"`, `device_command on/off/toggle`, an
`attribute_updated` event within 5 s of toggling, `remove_node`.
Also run the same suite against `matterjs-server` itself (npm run server) to
prove the tests encode the real behaviour, not our assumptions.
Verify: suite green on matterjs-server; green on backend-mc except documented
skips.

### T6 — Deploy  [Sonnet]
`server/Dockerfile` (rust:1-slim builder → debian:trixie-slim, `iputils-ping`,
`/data` volume, `HEALTHCHECK /health`), arm64 build via podman on the Pi.
Wire into `../../ha/docker-compose.yml` as the `matter-server` service on host
network, port 5580, same `/data` volume as the current Bun image. Add a
`make matter-rs` target in the repo Makefile that builds + restarts it.
Verify: `curl http://192.168.178.81:5580/health` → `ok`; HA Matter integration
shows the server; lamp entity toggles from HA.

**T6 validated (2026-09-03, local Mac, arm64):** local `cargo build --release
-p matter-server` and a `podman build --platform linux/arm64` of
`server/Dockerfile` both succeed as-is; `pkg-config`/`libssl-dev` were dropped
from the builder stage (whole dep tree is rustls, no openssl/native-tls per
`cargo tree`). Container runs `--backend mock` and `--backend mc` fine,
`/health` → `ok` on both; `rsm` isn't implemented yet (`--help` only lists
`mock`/`mc`, matches Milestone 2 not started). `docker compose ... config`
confirms the override replaces `build.context`/`image`/`environment` and
inherits `volumes`/`network_mode`/`userns_mode`/`user`/`restart` as the
override's comment promises. `playbooks/matter-rs.yml`'s `synchronize` step
was replaced (`ansible.posix` is not installed here) with a `tar`+`unarchive`
copy (delegate_to localhost) excluding `target/`, `conformance/`, `.venv`;
this does **not** reproduce rsync `--delete` — stale remote files can
accumulate across renames, not just adds. To deploy: (1) `make matter-rs`
from the repo root; (2) first build on a Pi 4/5 is ~10-15 min (rust:1-slim
`cargo build --release` of the whole workspace, no cache); (3) the Rust
server creates its own fabric on first boot, so the lamp must be
re-commissioned via the HA companion app even though `/data` is reused;
(4) podman's default OCI image format ignores Dockerfile `HEALTHCHECK`
(warning seen during build) — `podman ps` won't show a health column unless
the image/storage is built with `--format docker`; the app-level `/health`
endpoint still works fine either way. Not verified on the Pi itself or over
the network (out of scope for this pass — no ansible-playbook runs, no SSH
to 192.168.178.81 per task limits).

**Milestone 1 done when:** the lamp is commissioned through the HA companion
app + this server, appears as a light in HA, toggles from HA, and HA sees state
changes made at the lamp within a few seconds — on the Pi, from a cold restart
of the container (persistence works).

### T8 - `/health` body parity  [Sonnet, small]
`GET /health` must return `{"version": "<server version>", "node_count": <n>}`
(WIRE_PROTOCOL.md §25, measured against matter-server 1.4.0), not the literal
`ok`. `version` should be our own version string; `node_count` is the number of
commissioned nodes known to the backend. Update the container HEALTHCHECK only
if it stops passing (it checks the status code, not the body), and extend the
ws_smoke test to assert the JSON shape.

## 5. Milestone 2 — `backend-rsm` on official rs-matter

Everything below is verified against the checkout at `./rs-matter`
(commit 3a27068). Read these first, in order:

- `rs-matter/tests/src/bin/commissioner_tests.rs` — the canonical controller
  wiring: `Matter::init` + `matter.run(&crypto, &socket, &socket, NoNetwork)`
  as the transport pump, RCAC/ICAC via `onboard::cac::{RcacGenerator,
  IcacGenerator}`, controller NOC via `onboard::noc::NocGenerator`,
  `state.fabrics.add(...)` to install the controller fabric, then
  `onboard::Commissioner::{commission, complete_via_case}`.
- `rs-matter/rs-matter/tests/commissioning.rs` — in-process device +
  controller, IM read/invoke via `Exchange::initiate(matter, crypto, fab_idx,
  node_id)` + codegen'd clients (`exchange.on_off().toggle(1)`).
- `rs-matter/rs-matter/src/onboard.rs` — `CommissionOptions{fail_safe_secs,
  allow_test_attestation}`, `CommissionResult{fabric_index, device_node_id}`.
- `rs-matter/rs-matter/src/im/client.rs` — `ReadSender`, `WriteSender`,
  `InvokeSender`, `SubscribeSender`/`SubscribeOutcome`/`SubscribeEstablished`
  (raw IM client for wildcard reads and generic TLV).
- `rs-matter/rs-matter/src/persist.rs` — `DirKvBlobStore`, `Persist`,
  `KvBlobStore`; `examples/src/bin/onoff_light.rs` for the persist + mDNS +
  transport `select` wiring; `examples/src/common/mdns.rs` for `run_mdns`.
- `rs-matter/rs-matter/src/transport/network/btp/gatt/bluer.rs` —
  `scan`, `run_central` (BLE commissioner side, Linux BlueZ), for §6.

Known gaps in rs-matter's controller path (each is a task below):
(a) the controller's CA private key and NOC generator state are not persisted
— `Fabrics` persist via `Persist`, but the ICAC/RCAC signing key must be stored
by us; (b) `Commissioner::commission` does no `NetworkCommissioning`
(`AddOrUpdateWiFiNetwork`/`ConnectNetwork`) — fine for M1's on-network flow,
needed for §6; (c) attestation is accept-only (`allow_test_attestation` must
be `true`); (d) no client-side subscription lifecycle (liveness timeout,
re-subscribe, priming report handling) — we write it; (e) rs-matter futures
are not `Send` unless `sync-mutex` (marked "NOT ready yet") — run the whole
rs-matter stack on **one dedicated thread** with `futures_lite::block_on` +
`async-io`, and talk to it from tokio via channels (`async-channel`).
Do not try to run rs-matter inside the tokio runtime.

### R1 — Controller skeleton + persistent fabric  [Opus]
`crates/backend-rsm/src/stack.rs`: dedicated thread owning `Matter` (`StaticCell`),
`DirKvBlobStore` at `<storage>/rsm/`, `run_mdns` (builtin on Linux), UDP
socket on `[::]:0`, transport pump. On first boot: generate RCAC (+ICAC),
controller NOC (node id `112233`, vendor `0xFFF1` unless configured), IPK,
`fabrics.add`, and persist the ICAC signing key + certs in our own KV keys so
`NocGenerator::create` can be rebuilt after restart. Expose a `StackHandle`
(tokio side) with `call(|matter, crypto| async {...})` request/reply over
`async-channel`. Verify: restart keeps `fabric_id`, `compressed_fabric_id`
(`Fabric::compressed_fabric_id()`), and controller node id stable.

### R2 — Commissioning over IP  [Opus]
Parse QR (`MT:…`) and manual codes with `rs_matter::pairing`/`onboard`
helpers; discover `_matterc._udp` with the builtin mDNS querier filtered by
long/short discriminator (`CommissionableFilter`); `Commissioner::commission
(Address::Udp(addr), passcode, &opts, new_node_id, VALID_FOREVER)` then
`complete_via_case`. Allocate node ids monotonically from a persisted counter
(HA displays them; must be stable). Record `date_commissioned`.
Verify: commissions `chip-all-clusters-app` via `cargo xtask itest --suite
commissioner` style run, and the real lamp with an open window.

### R3 — Generic IM client: read/write/invoke with wildcards  [Opus]
Using raw `ReadSender`/`WriteSender`/`InvokeSender` (not the per-cluster
codegen'd clients — HA needs arbitrary paths). Implement `Backend::read`
(wildcard `AttrPath` → `AttrPath` IB with omitted fields; walk
`ReportDataResp` chunks → `(ConcretePath, MValue)`), `write` (TLV from
`MValue`, timed variant), `invoke` (timed variant; return response fields or
status). Convert `TLVElement` ↔ `MValue` generically (`rs_matter::tlv`).
Verify: full-node wildcard read of the lamp matches backend-mc's output for
the same lamp (diff test), byte-for-byte after name decoding.

### R4 — Subscription engine  [Opus]
Per node: one whole-node subscription (attrs `*/*/*`, all events), min 1 s /
max 60 s (match what matterjs-server requests — check
`ControllerCommandHandler.ts`); handle priming reports into the interview
cache; liveness = `max_interval + margin` → mark node unavailable, re-resolve
via mDNS, re-subscribe with backoff; emit `BackendEvent::{AttributeChanged,
Event, NodeAvailability}`. Handle `Lagged`-equivalents by re-reading.
Verify: toggle the lamp physically → `attribute_updated` within 5 s; unplug
the lamp → `node_updated` with `available: false`; re-plug → back to `true`
without a server restart.

### R5 — Admin operations  [Sonnet, after R3]
Via codegen'd clients on `Exchange::initiate`: `OperationalCredentials`
(`fabrics` read → `device_fabrics`; `RemoveFabric`; `UpdateFabricLabel`),
`AdministratorCommissioning::OpenCommissioningWindow` (generate passcode/
salt/verifier with `rs_matter::sc::pase` helpers; build manual + QR codes with
`rs_matter::pairing`), `AccessControl.acl` write, `Binding.binding` write,
`IcdManagement::{RegisterClient, UnregisterClient}` + reading
`ICDManagement` attributes for `get_icd_state`. Verify: same conformance
tests as backend-mc pass.

### R6 — Switch default backend  [Sonnet]
When T5's suite is green on `backend-rsm` including live tests, make `rsm`
the default and keep `mc` behind `--backend mc` for one release; delete it
after the Pi has run rsm for two weeks without a regression.

## 6. Milestone 3 — parity items that are real work

Each is independent; pick by user need.

- **BLE commissioning** (Wi-Fi/Thread lamp that is not yet on any network):
  rsm: `bluer::scan` by discriminator → `run_central` → `Btp::set_initiator
  (true)` → PASE over BTP → phase 1 → `NetworkCommissioning::
  AddOrUpdateWiFiNetwork`/`AddOrUpdateThreadNetwork` + `ConnectNetwork` using
  the stored credentials (`id` from `commission_with_code`) → `complete_via_case`
  over IP. Needs `bluer`+`zbus` features, BlueZ on the Pi, container with
  `--net host` and dbus socket. mc: `ble` feature (`btleplug`) +
  `MatterController::commission_ble`. [Opus]
- **OTA** (`check_node_update`, `update_node`, `initiate_ota_upload` +
  `POST /ota-upload/<id>`): mc has `serve_ota`; rsm has `ota_prov` cluster
  handler + `bdx`. DCL lookup of available versions is an HTTP client task
  (`rs-matter` has a small `ota-dcl` client). [Opus]
- **Thread diagnostics / border routers / network topology**
  (`get_thread_border_routers`, `get_thread_diagnostics`, `get_network_topology`,
  the two opt-in events): mDNS `_meshcop._udp` browse + OTBR REST + reading
  `ThreadNetworkDiagnostics`/`WiFiNetworkDiagnostics` from nodes. Pure
  protocol-crate work, backend-neutral. [Sonnet, after T1 shapes]
- **Vendor names** (`get_vendor_names`): DCL vendor list fetched at boot with
  cache on disk (matterjs-server does `--disable-dcl-seed` semantics; mirror
  the shape). [Sonnet]
- **import_test_node / diagnostics**: protocol-crate only. [Sonnet]
- **Real attestation** (PAA roots from DCL, CD verification): optional
  `--attestation strict`. [Opus]

## 7. Non-goals

Dashboard; `send_webrtc_provider_command`; Windows/macOS packaging; BLE proxy
package; embedded/no_std builds of the server.

## 8. Working agreements for subagents

- Verified crate/API facts in this file were read from source on 2026-09-03;
  if a signature differs when you build, trust the compiler and update this
  file in the same change.
- `cargo fmt`, `cargo clippy --workspace -D warnings`, `cargo test --workspace`
  before reporting done. Conformance suite (T5) for anything touching wire
  shapes.
- Never emit a wire field HA does not expect and never rename one; when in
  doubt, `grep` the python client's `models.py` dataclass for the field.
- Node ids, fabric ids, event numbers and timestamps are `u64` on the wire as
  bare JSON numbers. Test that `18446744069414584320` survives a round trip.
- Log with `tracing`; `set_loglevel` maps `critical/error/warning/notice/info/
  debug` (+ `fatal`, `warn` aliases) onto the reload filter.
- Keep secrets (Wi-Fi password, Thread dataset) out of every response, log
  line and `diagnostics` dump.
