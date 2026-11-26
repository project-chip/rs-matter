# rs-matter-fuzz

Fuzz targets for the code in `rs-matter` that handles data from other nodes: the parsers, the transports, and whole nodes.

The crate is not a member of the workspace. It needs a nightly toolchain and [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz):

```sh
cargo install cargo-fuzz
```

The prebuilt cargo-fuzz, which `cargo binstall` installs, is a musl binary that builds the targets for musl: with it, add `--target x86_64-unknown-linux-gnu` to the commands below.

Run the commands below from the root of the repository.

To list the targets and run one of them:

```sh
cargo +nightly fuzz list
cargo +nightly fuzz run tlv
```

A target runs until it finds a crash or until it is stopped. The input that caused a crash is saved in `fuzz/artifacts/<target>/`. To reproduce the crash, run the target with that file:

```sh
cargo +nightly fuzz run tlv fuzz/artifacts/tlv/crash-<hash>
```

CI runs each target for a minute on each push and pull request, from its seeds. The nightly run gives each target ten minutes and goes on from the corpus of the previous nightly runs, which it keeps in the cache of GitHub Actions. It also runs `node` and `sc`, which give data from peers to the crypto backend, with MbedTLS and OpenSSL.

The targets use the RustCrypto backend. The features `mbedtls` and `openssl` select one of the others:

```sh
cargo +nightly fuzz run --features mbedtls node
```

With OpenSSL, the node takes its random numbers from OpenSSL rather than from the generator of the target, so a run does not repeat exactly, and a crash may not happen again with the same input.

## Seeds

The inputs in `fuzz/seeds/<target>/` are where the fuzzer starts. To run a target with them, give the corpus directory first, as new inputs go to the first directory:

```sh
cargo +nightly fuzz run node fuzz/corpus/node fuzz/seeds/node
```

The seeds of `node` take it through interactions that the fuzzer would not find on its own:

| Seed | Messages |
|------|----------|
| `read-all` | A read of every attribute, which the node sends in four chunks |
| `read-events` | A read of the Basic Information attributes with a data version filter, and of all events |
| `subscribe` | A subscription, then a command and a write that change its attributes, with the answers to the two reports |
| `invoke-batch` | Three commands in one invoke request |
| `invoke-root` | Commands of the root endpoint: `TestEventTrigger`, `SetUTCTime`, `AttestationRequest`, `CertificateChainRequest`, `SetRegulatoryConfig` |
| `write` | Writes to attributes of Basic Information, General Commissioning and On/Off |
| `write-timed` | A timed write |
| `write-acl` | Writes to the access control list (all of it, then an entry added), then a read of it and of its events |
| `group-keys` | A group key set and a group key map, reads of them, then the removal of the key set |
| `commission` | A second fabric added over the CASE session (`ArmFailSafe`, `CSRRequest`, `AddTrustedRootCertificate`, `AddNOC`), CASE up to Sigma3 with that fabric, then the fail-safe expired |
| `update-noc` | `UpdateNOC` after a CSR for it, which fails, as the fabric of the session has no root certificate |
| `commission-pase` | The same as `commission` on the PASE session, as a commissioner does it, without CASE |
| `commissioning-window` | An enhanced commissioning window, PASE up to a wrong Pake3, `ArmFailSafe` while the window is open, then the revocation of the window |
| `commissioning-window-basic` | A basic commissioning window, then PASE with an invalid point in Pake1 |
| `case` | Sigma1 with a destination ID that matches no fabric, without and with resumption |
| `case-resume` | The resumption of the CASE session of the administrator, up to the end of it, then a resumption with a wrong MIC |
| `remove-fabric` | The removal of a fabric that does not exist, a new label for the fabric of the session, the removal of that fabric, then a read on the session |
| `secure-channel` | Secure channel messages that the node does not expect, an IM request that is not encrypted, and a datagram with a message extension |
| `bdx` | BDX transfers that the node does not expect |
| `subscribe-timeout` | A subscription, a keep-alive report that is answered, then one that is not, which the node sends again until it gives up and ends the subscription |
| `timeouts` | A response that is not acknowledged, which the node sends again until it gives up, then a write after its timed request has timed out |
| `fail-safe-timeout` | `ArmFailSafe` and `CSRRequest`, the expiry of the fail-safe, then `CSRRequest` again |
| `commissioning-window-timeout` | A basic commissioning window that closes after its timeout, then PASE |

The seeds of `clusters` take the cluster handlers of its node through their commands and their writable attributes:

| Seed | Messages |
|------|----------|
| `read-all` | A read of every attribute, which the node sends in many chunks |
| `subscribe` | A subscription to the light and the fan, then changes to them, with the answers to the reports |
| `on-off-level` | The commands of On/Off and Level Control, and writes to their attributes |
| `transitions` | A subscription, then transitions of Level Control and Color Control, Identify and a timed on, as time passes, with the answers to the reports |
| `color` | The commands of Color Control, and writes to its attributes |
| `scenes` | A scene with values for On/Off, Level Control and Color Control, then the commands of Scenes Management on it |
| `groups` | Two groups with keys and a scene in one of them, then the commands of Groups and Identify |
| `groupcast` | Groups joined with and without a key, then the other commands of Groupcast |
| `labels-bindings` | The lists of User Label and Binding, written whole and by items, then read |
| `modes` | Mode Select, with the mode that On/Off applies, and Laundry Washer Mode |
| `unit-testing-write` | Writes to attributes of Unit Testing of each data type, one of them timed |
| `unit-testing-lists` | Writes to lists of Unit Testing, whole and by items, among them a fabric-scoped list, then a read of them |
| `unit-testing-invoke` | The commands of Unit Testing, then a read of their events |
| `thermostat-fan` | The commands of Thermostat and Fan Control, and writes to their attributes |
| `time-sync` | The UTC time, a trusted time source, time zones and DST offsets for Time Synchronization, then a read of them after a while |
| `ota` | `QueryImage`, `ApplyUpdateRequest` and `NotifyUpdateApplied` to the OTA provider, then a default provider and `AnnounceOTAProvider` to the OTA requestor |
| `icd` | A client registered with ICD Management, then registered again, `StayActiveRequest` and the end of the active mode, then the removal of the client |
| `diag-logs` | Logs in the response, then a log over BDX, which the node sends and the requestor drives to its end, then a transfer that the requestor does not answer |
| `camera-streams` | A video stream allocated, changed and removed |
| `camera-settings` | Changes to the digital view of a video stream |
| `camera-zones` | Zones created, changed and removed, with a trigger, among them a zone that crosses itself, a copy of a zone, and the removal of a zone with a trigger |
| `camera-push` | A push transport allocated, found, triggered, changed and removed, over TCP, as its commands need large messages |
| `camera-webrtc` | A WebRTC session solicited, then one offered, with an answer, ICE candidates and its end, over TCP |

The seeds of `tcp` take the TCP transport through the ways in which its connections are used, and end:

| Seed | Steps |
|------|-------|
| `frames` | Frames each way on one connection, among them an empty one |
| `split-frame` | A frame in two pieces, then the end of the connection |
| `too-large` | A frame that is too large while a frame of the node is partly written |
| `eviction` | More peers than slots, so that an idle one is evicted for a new one |
| `backpressure` | A peer that reads slowly, so that the messages of the node wait for room in its queue |
| `connect` | Connections that the node opens: one that works, one that fails and one that never ends |
| `timeouts` | An idle connection whose close never ends, a reset, a failed accept and a failed keep-alive setting |

The program in `fuzz/seedgen` writes the seeds of `node`, `clusters` and `tcp`. It runs the same harness as the targets, to take the CSR of the node from its answer to `CSRRequest`, so that the NOCs in `commission` and `commission-pase` match the key of the node, and to answer each chunk of a report in the seeds of `clusters`. Run it again after a change to the input format, to the node of `clusters`, or when a seed no longer does what the tables say, for example when `AddNOC` in `commission` fails with `InvalidPublicKey` because the node draws random numbers in another order:

```sh
cargo run --manifest-path fuzz/seedgen/Cargo.toml
```

It prints how many messages the node sent for each seed of `node` and `clusters`. With `RUST_LOG=debug`, it also logs what the node does.

The seeds of `pairing_codes` are the QR codes and manual pairing codes of the tests of rs-matter, some of them invalid.

### Certificates from CHIP

The seeds of `cert` and `x509` are test certificates of [CHIP](https://github.com/project-chip/connectedhomeip), which is under the Apache License 2.0 like rs-matter. They come from commit `e36ff7cb82a3a92f5630db756d476ee1da7f2513` (2026-09-18). The directories below were the same on `master` on 2026-11-25.

| Seeds | From `credentials/test/` in CHIP |
|-------|----------------------------------|
| `cert` | `operational-certificates-error-cases/*-Cert.chip`: Matter certificates, each with one error |
| `cert` | `operational-certificates/*-Cert.chip-b64`: valid Matter certificates, decoded from Base64 |
| `x509` | `operational-certificates-error-cases/*-Cert.der`: the same as X.509 certificates |
| `x509` | `attestation/*-Cert.der`: PAA, PAI and DAC certificates |
| `x509` | `certification-declaration/*.der`: certification declarations |

The private keys next to them are left out. To update the seeds from a newer CHIP, in a checkout of it at `$CHIP`:

```sh
rm fuzz/seeds/cert/* fuzz/seeds/x509/*
cp $CHIP/credentials/test/operational-certificates-error-cases/*-Cert.chip fuzz/seeds/cert/
for f in $CHIP/credentials/test/operational-certificates/*-Cert.chip-b64; do
    base64 -d "$f" > "fuzz/seeds/cert/$(basename "$f" -b64)"
done
cp $CHIP/credentials/test/operational-certificates-error-cases/*-Cert.der fuzz/seeds/x509/
cp $CHIP/credentials/test/attestation/*-Cert.der fuzz/seeds/x509/
cp $CHIP/credentials/test/certification-declaration/*.der fuzz/seeds/x509/
```

Then change the commit above.

## Coverage

To see which code a target reaches from its seeds and a corpus:

```sh
cargo +nightly fuzz coverage node fuzz/corpus/node fuzz/seeds/node
llvm-cov report -instr-profile=fuzz/coverage/node/coverage.profdata \
    target/x86_64-unknown-linux-gnu/coverage/x86_64-unknown-linux-gnu/release/node
```

`llvm-cov` comes with the `llvm-tools` component of the nightly toolchain, under its `lib/rustlib/<triple>/bin/`.

## Targets

- `node`: a series of messages into a whole node, which processes each of them until it has nothing left to do. The node has an encrypted CASE session with an administrator, an encrypted PASE session, an encrypted CASE session over TCP with a second administrator, and a CASE session that it can resume. The messages can be on the three sessions, unencrypted, or raw datagrams. The input also says when time passes, as the clock of the node moves only then, so that its timers fire, such as for retransmissions, subscription reports and the end of a fail-safe. This covers the transport, the protocol handlers and the data model together. The target also checks what the node sends: each UDP datagram must fit in an IPv6 packet of the minimum MTU, each TLV message must be well-formed, and each IM response must decode.
- `clusters`: the same as `node`, with a node that has most of the cluster handlers of rs-matter, as the all-clusters app of CHIP has most of its clusters. The list is in `fuzz_targets/clusters/all_clusters.rs`. This covers the cluster handlers, which any controller with access to them reaches. The target runs slower than `node`, so it is a target of its own.
- `tlv`: TLV elements, with every accessor and `Display`. What reads must write back as the same bytes.
- `headers`: the two headers of a Matter message, which are the message header and the protocol header.
- `dedup`: message counters through the windows that detect duplicate messages, checked against a plain model of them.
- `im`: Interaction Model messages, both the requests that a node receives and the responses that a controller receives.
- `sc`: the secure channel messages that have their own parser rather than a TLV structure, which are message counter synchronization, Check-In and status reports.
- `bdx`: BDX messages and status reports.
- `tcp`: the TCP transport of a node, with TCP peers that connect, send bytes or frames, read slowly, close or reset as the input says, and messages that the node sends, so that it opens connections too. Time passes when the input says so. This covers the framing, the connection slots and their eviction, and the timeouts. The target checks that the node receives only frames that the peers sent, in order and once, that it writes only frames of its own messages and of its status report for a frame that is too large, and that it holds no more connections than it has slots for.
- `btp`: a series of BTP packets, sent through a BTP session in either role, and Matter BLE advertisements. The clock stays at 0, so BTP timers do not fire.
- `mdns`: mDNS queries to the responder of a node, and mDNS responses to the browser of a controller.
- `cert`: Matter (TLV) certificates, such as the certificates that a peer sends during CASE. When the conversion to X.509 succeeds, its output must be well-formed DER.
- `x509`: the DER data that a device sends during attestation, which is its certificates, its CSR and the certification declaration.
- `pairing_codes`: QR codes and manual pairing codes. What parses must encode back to the same values.

Note that most targets decode messages only. Apart from `node`, `clusters`, `tcp`, `btp` and `dedup`, they do not run the state machines of the protocols. Apart from `node`, `clusters`, `tcp`, `dedup`, `tlv`, `cert` and `pairing_codes`, they check only that nothing panics.

With `RUST_LOG` set, the `node`, `clusters` and `tcp` targets log what the node does, which helps to understand a crash: `RUST_LOG=debug cargo +nightly fuzz run node <crash file>`.

The targets have their own time driver for `embassy-time`, in `fuzz_targets/clock.rs`, with a clock that moves only when a target moves it, so that a run does the same each time. For this, the crate does not use the `os` features of the rs-matter crates, which bring the time driver for `std`.
