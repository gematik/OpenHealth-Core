
/// Interface for Elliptic Curve Diffie-Hellman key exchange operations.
pub trait Ecdh {
    fn spec(&self) -> &EcdhSpec;

    /// Computes the shared secret using the other party's public key.
    fn compute_secret(&self, other_public_key: &EcPublicKey) -> Vec<u8>;
}

/// Specification for ECDH key exchange operations.
pub struct EcdhSpec {
    pub curve: EcCurve,
}

impl EcdhSpec {
    pub fn new(curve: EcCurve) -> Self {
        Self { curve }
    }
}

/// Creates a native ECDH key exchange instance.
pub(crate) fn native_create_key_exchange(
    spec: &EcdhSpec,
    scope: &CryptoScope,
    private_key: &EcPrivateKey,
) -> Box<dyn Ecdh> {
    unimplemented!()
}