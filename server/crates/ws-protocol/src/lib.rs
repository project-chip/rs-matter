//! Backend-agnostic HA/matterjs-server wire protocol (PLAN.md §0.1). Everything here speaks
//! either plain Rust values (the `Backend` trait) or the exact JSON shapes in
//! `docs/WIRE_PROTOCOL.md` — no Matter stack lives in this crate.

pub mod backend;
pub mod mock;
pub mod names;
pub mod path;
pub mod server;
pub mod value;
pub mod wire;

pub use backend::{Backend, BackendEvent};
pub use mock::MockBackend;
pub use names::{CommandNames, MatterNames, NoNames};
pub use path::{AttrPath, ConcretePath};
pub use server::{Connection, LogControl, NoLogControl, Server, ServerConfig};
pub use value::MValue;
pub use wire::{ErrorCode, ErrorResponse, Event, Request, ServerError, SuccessResponse};
