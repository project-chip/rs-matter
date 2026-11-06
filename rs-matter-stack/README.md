# rs-matter-stack

Native Rust implementation of the Matter (Smart-Home) ecosystem - the assembly of the node over a network driver

NOTE: This crate can be used on its own, but to avoid future breakage, prefer depending only on the `rs-matter` crate, which re-exports it. Also, all `rs-matter-*` crates share one version, so the minor version of this crate might change without any breaking changes to it, or without any changes at all.

## Wireless runners without BLE

For a device with saved fabric and Wi-Fi or Thread credentials,
`WifiMatterStack::run_wifi_only` and `ThreadMatterStack::run_thread_only` start the
operational network with a `WifiDriver` or `ThreadDriver` that does not implement
`GattDriver`. Call `startup` first to load the saved state. This path serves
commissioning windows over IP and never starts BLE; the existing `run` and
`run_coex` methods retain their BLE commissioning behavior.
