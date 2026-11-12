# rs-matter-stack

Native Rust implementation of the Matter (Smart-Home) ecosystem - the assembly of the node over a network driver

NOTE: This crate can be used on its own, but to avoid future breakage, prefer depending only on the `rs-matter` crate, which re-exports it. Also, all `rs-matter-*` crates share one version, so the minor version of this crate might change without any breaking changes to it, or without any changes at all.

## Embedded operational TCP

UDP remains the default. Enable the `operational-tcp` feature for stack integration; UDP-only
builds then avoid reserving the listener's frame buffers (`operational-tcp` / `stack-tcp` through
the `rs-matter` facade). A network stack can implement `TcpStack`
and return `Some(self)` from `NetStack::tcp(&self)`.
`StdNetStack` implements both `NetStack` and `TcpStack` for host applications and tests.

The runner binds TCP on the same Matter port as UDP (5540 by default), sets the
live TCP discovery capability after binding succeeds, and clears it when the
listener stops. It reuses the transport's existing `T=6` mDNS encoding.

The embedded server uses Matter's four-byte little-endian length prefix and
fixed buffers for one normal-sized receive frame and two outgoing frames. It
accepts one active peer; extra peers are closed. The writer runs independently
of the shared UDP sender, with configurable idle and send timeouts. A peer
whose outgoing queue fills is closed rather than delaying UDP traffic or
allocating more buffers. Dropping a peer releases the driver's socket resources.
