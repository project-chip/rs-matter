# rs-matter-server

A Home Assistant compatible **Matter controller server in Rust**: one small
binary that speaks the same WebSocket protocol as
[`matterjs-server`](https://github.com/matter-js/matterjs-server) and
[`python-matter-server`](https://github.com/home-assistant-libs/python-matter-server),
so Home Assistant's Matter integration can talk to it unmodified.

Built for small always-on hardware. The reference implementations need more RAM
than a 512 MB Raspberry Pi Zero 2 W has left after Home Assistant is running;
this one idles at **~7 MB**.

> **Status: early.** The protocol layer is complete and verified against the
> real Home Assistant client. Commissioning a device has **not** been proven
> end to end yet — see [Status](#status). Do not expect a working smart home
> from this today.

## Footprint

Same machine, same Matter server version, idle with no commissioned nodes:

|            | Node 22 | Bun (compiled) | **this** |
| ---------- | ------: | -------------: | -------: |
| Image      |  615 MB |         207 MB | **136 MB** |
| RSS, idle  |  185 MB |         186 MB |  **7 MB** |
| Executable |       — |          86 MB | **6.6 MB** |

RSS was measured on the Pi Zero 2 W itself; images are `linux/arm64`.

## Build and run

```sh
cd server
cargo run -p matter-server -- --backend mc --storage-path ~/.rs-matter-server --port 5580

curl http://localhost:5580/health
# then point Home Assistant's Matter integration at ws://<host>:5580/ws
```

Container (the runtime image carries only the binary, `curl` and `ping`):

```sh
podman build -t rs-matter-server .
podman run -d --network host -v /srv/matter:/data rs-matter-server
```

Host networking is required — Matter needs mDNS and IPv6 multicast.

## Architecture

```
crates/ws-protocol/   the entire HA wire protocol: commands, events, error
                      codes, attribute paths, TLV<->JSON, the Backend trait
crates/matter-names/  Matter cluster/command/event name tables, generated
                      from the 1.5.1 IDL (device_command by name, node_event)
crates/backend-mc/    Backend impl on the `matter-controller` crate  [works today]
crates/backend-rsm/   Backend impl on rs-matter                      [not written yet]
crates/matter-server/ the binary: HTTP + WebSocket listener, CLI, wiring
conformance/          pytest suite driving HA's real python client
```

The protocol layer never touches a Matter stack directly — everything goes
through one `Backend` trait, so the stack underneath can be swapped without
touching a line of wire code. Pick at runtime with `--backend`.

**Why two backends.** This repo is a fork of
[`project-chip/rs-matter`](https://github.com/project-chip/rs-matter), and
rs-matter is the intended destination: it is the official stack and it now has
a working commissioner (`onboard::Commissioner`), an IM client, mDNS and BLE.
What it does not yet have on the controller side is persistence of the
controller's own CA material, a subscription lifecycle, or network
provisioning — all of which the third-party
[`matter-controller`](https://crates.io/crates/matter-controller) crate already
provides. So `backend-mc` exists to get something working now, and
`backend-rsm` is the target. The trait boundary is what makes that switch
cheap.

## Status

Verified:

- The full wire protocol, extracted from the matterjs-server TypeScript with
  line-level citations (`docs/WIRE_PROTOCOL.md`) — frames, error codes, the
  event envelope, tag-based attribute values, node objects, credential
  handling.
- **12/12 conformance tests pass** using Home Assistant's own
  `python-matter-server` client, against this server *and* against the real
  matterjs-server, so the tests encode observed behaviour rather than
  assumptions.
- Deployed and healthy on a Raspberry Pi Zero 2 W alongside Home Assistant;
  HA connects, subscribes and stays connected. mDNS discovery of real
  commissionable devices on the LAN works.

Not yet working:

- **Commissioning aborts** partway through attestation when the peer answers
  an invoke with a message-level `StatusResponse{Busy}` — legal per spec, and
  what a resource-constrained device does under back-to-back requests.
  `matter-interaction` 0.4.1 has no `StatusResponse` handling in its invoke
  path and raises a framing error, which kills the commissioning attempt.
  Reproduced against an rs-matter software device over LAN and loopback, and
  through HA's client. Everything downstream of commissioning — reading,
  commands, subscriptions, `attribute_updated` events — is therefore unproven
  against a real device.
- `backend-rsm` does not exist yet.
- No BLE, and no Wi-Fi/Thread provisioning: a device must already be on the IP
  network. Commission it with a phone app first, then share it here through a
  commissioning window.
- `/health` returns `ok` instead of matterjs-server's JSON body.

`docs/PLAN.md` carries the full task breakdown and the remaining parity gaps.

## Tests

```sh
cargo test --workspace          # unit + a WS smoke test against the real binary

cd conformance
make test-mock                  # in-memory backend
make test-mc                    # the matter-controller backend
make test-matterjs              # the same suite against matterjs-server, as an oracle
```

The conformance suite installs Home Assistant's client from matterjs-server, so
it needs network on first run.

## Credit

- [`project-chip/rs-matter`](https://github.com/project-chip/rs-matter) — the
  Matter stack this repo forks and targets.
- [`matter-js/matterjs-server`](https://github.com/matter-js/matterjs-server)
  (Apache-2.0) — the reference implementation whose wire protocol this
  reproduces, and the source of the conformance client.
- [`matter-controller`](https://crates.io/crates/matter-controller) — the crate
  behind the currently working backend.

Apache-2.0, like its upstreams.
