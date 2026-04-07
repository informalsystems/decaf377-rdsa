#![cfg_attr(not(feature = "std"), no_std)]
#![doc = include_str!("../README.md")]

#[cfg(not(feature = "std"))]
extern crate alloc;

mod domain;
mod error;
mod hash;
mod signature;

mod signing_key;
mod verification_key;

pub use domain::{Binding, Domain, SpendAuth};
pub use error::Error;
pub use hash::HStar;
pub use signature::Signature;
pub use signing_key::SigningKey;
pub use verification_key::{VerificationKey, VerificationKeyBytes};

pub use cycles_curve_bn254::Fr;

#[cfg(feature = "std")]
pub mod batch;
