# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased
* Persistent subscriptions now supported
  * Subscriptions can be persisted and resumed across a reboot (opt-in via `set_persist_subscriptions`, off by default)
  * Fix: A subscription is no longer pinned to its establishing session which was incorrect
  * Fix: A not-yet-primed subscription with a `MinIntervalFloor` of 0 is now reported immediately instead of never
  * Fix: A failed report no longer advances the subscription's watermark, so the changes/events it was carrying are retried instead of silently dropped
* (Breaking) ICD support: Check-In Protocol, ICD cluster handler, mDNS advertisements (#501)
* Warn on packet retransmission (#500)
  * (Breaking) Rename feature `debug-tlv-payload` to `log-tlv-payload`
* MCSP Protocol Implementation (#499)
* BTP: handle no-preference handshake MTU of 0 (#497)

## [0.2.0] - 2026-06-25
* Initial release
