use cycles_curve_bn254::Fr;
use sha3::{Digest, Keccak256};

/// Provides H^star, the hash-to-scalar function.
/// Uses keccak256 (EVM-compatible) instead of BLAKE2b.
pub struct HStar {
    hasher: Keccak256,
}

impl Default for HStar {
    fn default() -> Self {
        let mut hasher = Keccak256::new();
        hasher.update(b"decaf377-rdsa---");
        Self { hasher }
    }
}

impl HStar {
    /// Add `data` to the hash, and return `Self` for chaining.
    pub fn update(mut self, data: impl AsRef<[u8]>) -> Self {
        self.hasher.update(data.as_ref());
        self
    }

    /// Consume `self` to compute the hash output.
    pub fn finalize(self) -> Fr {
        Fr::from_le_bytes_mod_order(self.hasher.finalize().as_slice())
    }
}
