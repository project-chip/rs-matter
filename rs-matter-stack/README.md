# rs-matter-stack

Native Rust implementation of the Matter (Smart-Home) ecosystem - the assembly of the node over a network driver

NOTE: This crate can be used on its own, but to avoid future breakage, prefer depending only on the `rs-matter` crate, which re-exports it. Also, all `rs-matter-*` crates share one version, so the minor version of this crate might change without any breaking changes to it, or without any changes at all.

## Embedded operational TCP

UDP remains the default: `NetStack::tcp(&self)` defaults to `None::<NoTcp>`, so
UDP-only network stacks compile unchanged without Cargo feature flags. A network
stack that supports operational TCP implements `NetTcpStack` over caller-owned
static `TcpBuffers` and returns `Some(...)` from `NetStack::tcp(&self)`.
`StdNetStack::with_tcp(&buffers)` enables operational TCP for host applications
and tests (`StdNetStack::new()` remains UDP-only).

The runner binds TCP on the same Matter port as UDP (5540 by default), sets the
live TCP discovery capability (`T=4` for server-only or `T=6` for client+server)
only after binding succeeds, and clears it when the listener stops.
