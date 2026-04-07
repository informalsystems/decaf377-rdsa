/// Abstracts over different signature domains.
///
/// This design is described [at the end of §5.4.6][concretereddsa] of the Zcash
/// protocol specification: the generator used for the signature scheme is left
/// as an unspecified parameter, chosen differently for each signature domain.
///
/// To handle this, we encode the domain as a type parameter.
///
/// [concretereddsa]: https://zips.z.cash/protocol/protocol.pdf#concretereddsa
pub trait Domain: private::Sealed {}

/// A type variable corresponding to Zcash's `BindingSig`.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Binding {}
impl Domain for Binding {}

/// A type variable corresponding to Zcash's `SpendAuthSig`.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum SpendAuth {}
impl Domain for SpendAuth {}

pub(crate) mod private {
    use super::*;
    use sha3::{Digest, Keccak256};

    fn hash_to_group(input: &[u8]) -> cycles_curve_bn254::Element {
        let hash = Keccak256::digest(input);
        cycles_curve_bn254::Element::encode_to_curve(
            &cycles_curve_bn254::Fq::from_le_bytes_mod_order(hash.as_slice()),
        )
    }

    pub trait Sealed: Copy + Clone + Eq + PartialEq + core::fmt::Debug {
        fn basepoint() -> cycles_curve_bn254::Element;
    }

    impl Sealed for Binding {
        fn basepoint() -> cycles_curve_bn254::Element {
            hash_to_group(b"decaf377-rdsa-binding")
        }
    }

    impl Sealed for SpendAuth {
        fn basepoint() -> cycles_curve_bn254::Element {
            cycles_curve_bn254::Element::generator()
        }
    }
}

pub(crate) use private::Sealed;

/// Returns the Binding domain basepoint (for Solidity constant derivation).
/// Precomputed via hash_to_group(b"decaf377-rdsa-binding") with keccak256.
#[cfg(any(test, feature = "std"))]
pub fn binding_basepoint() -> cycles_curve_bn254::Element {
    Binding::basepoint()
}

#[cfg(test)]
mod tests {
    use super::*;
    use cycles_curve_bn254::AffinePoint;

    #[test]
    fn print_binding_basepoint_for_solidity() {
        let bp = binding_basepoint();
        let affine: AffinePoint = bp.into();
        let inner = affine.inner();
        // Print for copy-paste into Solidity (use: cargo test print_binding_basepoint -- --nocapture)
        eprintln!("BINDING_BASEPOINT_X = {}", inner.x);
        eprintln!("BINDING_BASEPOINT_Y = {}", inner.y);
    }
}
