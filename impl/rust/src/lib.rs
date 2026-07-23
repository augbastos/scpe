//! scpe-verify: a Rust library crate exposing the [`scpe`] verification module.
//!
//! See `src/scpe.rs` for the actual SCPE scpe/0.1 verification logic — this
//! file only wires it up as a library target so both the `scpe-verify`
//! binary and `tests/vectors.rs` can use it.

pub mod scpe;
