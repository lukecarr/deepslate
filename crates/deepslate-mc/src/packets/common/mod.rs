//! Common packets that are stable across protocol versions.
//!
//! These packets have the same format in all supported versions.

pub mod handshake;

pub use handshake::{Handshake, NextState};
