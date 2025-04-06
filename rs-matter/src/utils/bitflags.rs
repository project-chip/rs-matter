//! A module that re-exports the standard `bitflags!` macro if `defmt` is not enabled, or `defmt::bitflags!` if `defmt` is enabled.

#[cfg(not(feature = "defmt"))]
pub use bitflags::bitflags;

#[cfg(feature = "defmt")]
pub use defmt::bitflags;
