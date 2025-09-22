use std::sync::Arc;
use crate::error::CryptoResult;
use crate::key::key::{KeySize, PrivateKey, PublicKey};
use crate::ossl;
use crate::utils::byte_unit::{ByteUnit, BytesExt};

#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct WrappedKey(Vec<u8>);

impl AsRef<[u8]> for WrappedKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
impl KeySize for WrappedKey {
    fn size(&self) -> ByteUnit {
        self.0.len().bytes()
    }
}


#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct SharedSecret(Vec<u8>);

impl SharedSecret {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
impl SharedSecret {
    #[cfg_attr(feature = "uniffi", uniffi::constructor)]
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> Vec<u8> { self.0.clone() }
}

#[derive(Clone)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum MlkemSpec {
    MlKem512,
    MlKem768,
    MlKem1024,
}

impl MlkemSpec {
    fn algorithm(&self) -> &'static str {
        match self {
            MlkemSpec::MlKem512 => "ML-KEM-512",
            MlkemSpec::MlKem768 => "ML-KEM-768",
            MlkemSpec::MlKem1024 => "ML-KEM-1024",
        }
    }

    pub fn decapsulator(self) -> CryptoResult<MlkemDecapsulator> {
        let dec = ossl::mlkem::MlkemDecapsulation::create(self.algorithm())?;
        Ok(MlkemDecapsulator { spec: self, dec })
    }

    pub fn encapsulator(self, public_key: PublicKey) -> CryptoResult<MlkemEncapsulator> {
        let enc = ossl::mlkem::MlkemEncapsulation::create(self.algorithm(), public_key.as_ref())?;
        Ok(MlkemEncapsulator { spec: self, enc })
    }
}

pub struct MlkemEncapsulator {
    spec: MlkemSpec,
    enc: ossl::mlkem::MlkemEncapsulation,
}

impl MlkemEncapsulator {
    pub fn encapsulate(&self) -> CryptoResult<(WrappedKey, SharedSecret)> {
        let (wrapped, secret) = self.enc.encapsulate()?;
        Ok((WrappedKey(wrapped), SharedSecret(secret)))
    }
}

pub struct MlkemDecapsulator {
    spec: MlkemSpec,
    dec: ossl::mlkem::MlkemDecapsulation,
}

impl MlkemDecapsulator {
    pub fn decapsulate(&self, wrapped_key: WrappedKey) -> CryptoResult<SharedSecret> {
        let secret = self.dec.decapsulate(wrapped_key.as_ref())?;
        Ok(SharedSecret::new(secret))
    }

    pub fn public_key(&self) -> CryptoResult<PublicKey> {
        Ok(PublicKey::new(self.dec.get_encapsulation_key()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(spec: MlkemSpec) {
        let dec = spec.clone().decapsulator().expect("decapsulator");

        let pk = dec.public_key().unwrap();
        let enc = spec.clone().encapsulator(pk).expect("encapsulator");
        let (wrapped, ss_enc) = enc.encapsulate().expect("encapsulate");

        let ss_dec = dec.decapsulate(wrapped).expect("decapsulate");

        // Shared secret must match
        assert_eq!(ss_enc.as_bytes(), ss_dec.as_bytes(), "shared secret equality");
    }

    #[test]
    fn mlkem512_roundtrip() {
        roundtrip(MlkemSpec::MlKem512);
    }

    #[test]
    fn mlkem768_roundtrip() {
        roundtrip(MlkemSpec::MlKem768);
    }

    #[test]
    fn mlkem1024_roundtrip() {
        roundtrip(MlkemSpec::MlKem1024);
    }
}