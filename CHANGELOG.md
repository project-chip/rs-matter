# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
* Fix: when the session table is full, a new `CASESigma1` / `PBKDFParamRequest` evicts a session and proceeds, rather than being answered with Busy; Busy is sent only if no session can be evicted (#587)
* More fixes for Sleepy End Devices, now primarily for the initiator (#584)
  * Fix: as CASE / PASE initiator, apply the responder's MRP session parameters (Sigma2, Sigma2_Resume, PBKDFParamResponse) to the new session instead of keeping our own defaults
  * Fix: the session parameters of CASE / PASE handshake messages are now always sent, by initiator and responder alike, and carry the SAI / SII (the SII as over mDNS), the ICD's Active Mode Threshold as SAT, and the data model / interaction model revisions and specification version the spec requires
  * Fix: peer-advertised SAI / SII values above one hour are ignored, like zero ones
  * Fix: MRP paces each (re)transmission by the peer's idle interval (SII) unless we heard from it within its active threshold (SAT)
  * Fix: a peer that does not advertise its SAI / SII / SAT is assumed to use the spec defaults (300 / 500 / 4000 ms), rather than our own configured values or a 5000 ms SII; `default_peer_mrp_params` is removed, and a session set up without a handshake takes its peer's parameters from the new `ReservedSession::set_peer_mrp_params`
  * Fix: an ICD with no configured SII advertises its slow polling interval as its SII, rather than none (which had peers assume 500 ms)
  * New: an ICD advertises its Active Mode Threshold in the `SAT` mDNS TXT key
  * Breaking: `IcdAdvertisement` now describes every ICD (SIT-only too)
  * Breaking: `CaseInitiator::perform` / `PaseInitiator::perform` take an optional `PeerMrpParams` - the peer's mDNS TXT hint - seeding the handshake
* Fix: correctly order C1 and C2 in the BTP GATT handshake to fix comissioning over bluez/bluer (#582)
* Fix: `LitIcdMgmtHandler::CLUSTER` no longer claims the Dynamic SIT/LIT feature, which the device did not implement; `LitIcdMgmtHandler::CLUSTER_DSLS` claims it, backed by the new `LitIcd::set_sit_required` (#580)
* Breaking: the ICD Management cluster is now split into two variants: SIT-only and LIT  (#580)
* Breaking: ICD LIT cluster handler: new, separate slow poll parameter (SII) for when the device operates in SIT mode, different form its (potentially much longer) LIT SII (#580)
* Fix: unresumed persistent sessions that fail to report to their subscribers were retried indefinitely (#580)
* Breaking: simplify the ICD support by running everything and just informing the user about the current ICD state (#579)
* Fix: an unsecured session initiated by the device (e.g. for an ICD Check-In) no longer swallows a peer-initiated `CASESigma1` / `PBKDFParamRequest` from the same address, which made CASE fail right after a Check-In (#579)
* Fix: the transport no longer wakes every 50/100 ms while idle; new `IfMutex::wait_until` (#578)
* Fan Control cluster handler (`FanControlHandler` / `FanControlHooks`) (#577)
* Fix the Mode Select cluster handler to set the current mode into the hooks upon startup (#576)
* Fix the Thread Diagnostics cluster handler to not return "invalid action" when the routes table is reported with chunked reads (#575)
* Breaking: remove `AsyncHandler::read_awaits/write_awaits/invoke_awaits`, as they are no longer used (#574)
* `Matter::kv` now returns a named type - `MatterKvBlobStoreAccess` (#572)
* Breaking: rework the persistence story for level-control, on-off and color-control in that `rs-matter` persists everything (#568)
* Thermostat, Electrical Power Measurement, Electrical Energy Measurement and Power Topology cluster handlers, plus the Thermostat and Electrical Sensor device types (#568)
* Log which event overflowed the event ring buffer, and how big it is (#568)
* Make the `fabrics`, `sessions`, `rtc` and `basic_info_settings` fields in `MatterState` public and deprecate `Matter::with_rtc` (#570)
* New APIs: `Session::is_reserved`, `Session::is_expired`, `Session::expire`, `Sessions::iter_mut`, `Sessions::remove_where`, `Sessions::expire_where` (#570)
* Fix: session removal notification should support multiple waiters (#570)
* Fix, breaking: `Commissioner` contained the `&'a mut NocGenerator<'a>` anti-pattern; fixed by introducing an extra lifetime - `'b` (#567)
* Fix: `Commissioner::commission` should remove any stale sessions (#567)
* Process incoming "Session not found" messages from the peers by removing these sessions on our end (#567)
* Fix: make `tokio` and `tokio-stream` optional, gated behind `bluer` (#564)
* Fix: gate the BlueZ zbus proxies behind target_os = "linux" (#562)
* Fix: never answer with "no session" messages expecting no answer (#560)
* Fix: faster clusters' codegen (#558)
* Fixes for issues uncovered by new unit tests (#557):
  * Mbedtls accepted off-curve points on public-key import;
  * Openssl/mbedtls panicked on CCM decrypt of input shorter than the tag;
  * Derived tlv_iter emitted a struct start for datatype = "list" structs;
  * TLVSequenceTLVIter mis-tracked container nesting (debug panic, missing end token);
  * DirKvBlobStore::load failed on an exact-fit buffer; Dir/File stores now report `ErrorCode::BufferTooSmall`;
  * ArmFailSafe(0) while idle should be a no-op;
  * AddGroup should validate the name before mutating;
  * `acl_add_init` now rejects PASE auth mode;
  * A fresh session's replay window is seeded by the first received message;
* Miri support: fixed an aliasing issue in `PooledBuffers` and a `transmute` flagged by miri; unit tests for covering all unsafe code; miri CI run on those unit tests (#556)

## [0.4.1] - 2026-09-17
* Fix: `NameSliceIter::next_back` in the builtin mDNS responder always returned `None`, breaking reverse label iteration (#554)
* Fix: BTP ACKs sender was wrongly using the RECV timeout of 15s for sending (#554)
* Fix: the `respond` module now uses ~ 2x less memory (#554)

## [0.4.0] - 2026-09-14
* Fix: A persisted subscription is now resumed under the subscription ID it had before the reboot (#552)
* Commissioning handover: `Matter::suspend_commissioning` and `Matter::resume_commissioning` - the building block for NFC (NTL) commissioning, where phase 1 runs on the NFC subsystem (#550)
* `xtask onboard` - generate a device's manual pairing code, QR code text, NFC NDEF message, the QR code itself, etc. etc. from the commissioning parameters (#550)
* Fix: Certificate serial numbers are now always valid DER INTEGERs: the CA generators encode a drawn `u64` rather than using raw random bytes, and `validate_serial_number` rejects a redundant leading `0xFF` as well as a redundant leading `0x00` (#549)
* (Breaking) Update to all RustCrypto crates as well as `rand_core` to their latest versions (#548)
* (Breaking) Update the non-crypto dependencies to their latest majors: `pinned-init`, `strum`, `num-derive` and a few others (#548)
* (Breaking) Better matching syntax; utils for non-networking system clusters (#547)
* (Breaking) Streamline the factory reset and startup story of all clusters with persistence (#546)
* (Breaking) Retire `GenDiag::reboot_count` and `GenDiag::uptime_ms` as they are now implemented directly in `rs-matter` (#543)
* Add PAF and NTL options to `DiscoveryCapabilities`; `QrPayload::as_ndef` (#543)
* Streamline the logging of the E2E test drivers (#542)
* Commissioning - trying to close a non-open comm window should return an error (#541)
* Commissioning over PASE - fix a spurious SessionNotFound error (#541)
* Support for PICS and the TH tool (#541)
* Mode Select and Mode base clusters (#540)
* API notifying user code on failed subscription reporting (#539)
* Improved handling of RX and TX timeouts (#538)
* Advertise and use **all** of a node's IPv6 addresses rather than just one (#537)
* (Breaking) Phase 2 of commissioning always goes through operational discovery now (#537)

## [0.3.0] - 2026-08-20
* Groupcast **sending** APIs (`groups` feature): `Exchange::initiate_group` and `ImClient::group_invoke_with`; the `onoff_light_switch` example and the `light_tests` switch endpoint now act on *group* binding targets
* (Breaking) `Matter::is_commissioned` renamed to `Matter::has_fabrics` (#525)
* New `Matter::comm_window_state` method useful downstream for figuring out if the commissioning transport should be enabled (#525)
* Network Recovery data-model support - provisional in Matter 1.6 (#523)
* Groupcast cluster handler support (Matter 1.6) - available when the `groups` feature is enabled (#521)
* Fix CASE Sigma2 retransmissions with randomized ECDSA (#520)
* (Breaking) Optional Time Zones support in the Time Sync Cluster Handler, trait `TimeSync` split into `TimeZones`, `NtpClient` and `NtpServer` (#517)
* (Breaking) Handler lifecycle hook - cluster handlers can now participate in the node's persistence lifecycle (#516)
* (Breaking) The code-generated (sync) `ClusterHandler` trait now also carries a defaulted `run` method, mirroring `ClusterAsyncHandler` (#517)
* (Breaking) Supported Matter Spec Version is now 1.6.0 (#510)
* Exchange initiators - use a random exchange ID (#509)
* Support for commissioning over BTP (#507)
* A new - ReportDataHandler - handler for InteractionModel (#506)
* Multicast groups support is now under a `groups` opt-in feature to save flash size (#505)
* CASE session resumption support - under a `case-resumption` Cargo feature (#503)
* Persistent subscriptions now supported (#504)
  * Subscriptions can be persisted and resumed across a reboot (opt-in via a new `persistent-subscriptions` Cargo feature, off by default)
  * New `case-responder-only` Cargo feature (off by default): `Exchange::initiate` never establishes a new CASE session (it only reuses an existing one, else fails), letting the linker drop the CASE initiator and mDNS resolver from a pure accessory that only reports over sessions its peers established
  * Fix: A subscription is no longer pinned to its establishing session which was incorrect
  * Fix: A not-yet-primed subscription with a `MinIntervalFloor` of 0 is now reported immediately instead of never
  * Fix: A failed report no longer advances the subscription's watermark, so the changes/events it was carrying are retried instead of silently dropped
* Secure Channel Handler (#502)  
* (Breaking) ICD support: Check-In Protocol, ICD cluster handler, mDNS advertisements (#501)
* Warn on packet retransmission (#500)
  * (Breaking) Rename feature `debug-tlv-payload` to `log-tlv-payload`
* MCSP Protocol Implementation (#499)
* BTP: handle no-preference handshake MTU of 0 (#497)

## [0.2.0] - 2026-06-25
* Initial release
