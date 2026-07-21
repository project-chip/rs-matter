# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased
* (Breaking) Handler lifecycle hook - cluster handlers can now participate in the node's persistence lifecycle
* (Breaking) The code-generated (sync) `ClusterHandler` trait now also carries a defaulted `run` method, mirroring `ClusterAsyncHandler`
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
