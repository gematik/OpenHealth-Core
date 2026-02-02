// SPDX-FileCopyrightText: Copyright 2025 gematik GmbH
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// *******
//
// For additional notes and disclaimer from gematik and in case of changes by gematik,
// find details in the "Readme" file.

use crate::error::{CryptoError, CryptoResult};
use crate::key::SecretKey;
use crate::ossl;
use core::fmt;
use std::mem::ManuallyDrop;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub type MlkemSharedSecret = SecretKey;

/// Wrapped KEM key produced by encapsulation.
#[derive(Zeroize, ZeroizeOnDrop, PartialEq, Eq)]
pub struct MlkemWrappedKey {
    bytes: Vec<u8>,
}

/// Private key bytes for ML-KEM. Zeroized on drop.
#[derive(Zeroize, ZeroizeOnDrop, PartialEq, Eq)]
pub struct MlkemPrivateKey(Vec<u8>);

impl MlkemPrivateKey {
    pub fn new(bytes: Vec<u8>) -> CryptoResult<Self> {
        if bytes.is_empty() {
            return Err(CryptoError::InvalidKeyMaterial { context: "private key must not be empty" });
        }
        Ok(Self(bytes))
    }

    pub fn into_inner(self) -> Vec<u8> {
        // Prevent drop from zeroizing before we take ownership of the bytes.
        let mut this = ManuallyDrop::new(self);
        std::mem::take(&mut this.0)
    }
}

impl AsRef<[u8]> for MlkemPrivateKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for MlkemWrappedKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MlkemWrappedKey").field("len", &self.bytes.len()).finish()
    }
}

impl MlkemWrappedKey {
    pub fn new(bytes: impl Into<Vec<u8>>) -> CryptoResult<Self> {
        let bytes = bytes.into();
        if bytes.is_empty() {
            return Err(CryptoError::InvalidKeyMaterial { context: "wrapped key must not be empty" });
        }
        Ok(Self { bytes })
    }

    pub fn into_inner(self) -> Vec<u8> {
        self.bytes.clone()
    }
}

impl AsRef<[u8]> for MlkemWrappedKey {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl TryFrom<Vec<u8>> for MlkemWrappedKey {
    type Error = CryptoError;
    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        MlkemWrappedKey::new(value)
    }
}

/// Public encapsulation key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MlkemEncapsulationKey(Vec<u8>);

impl MlkemEncapsulationKey {
    pub fn new(bytes: impl Into<Vec<u8>>) -> CryptoResult<Self> {
        let bytes = bytes.into();
        if bytes.is_empty() {
            return Err(CryptoError::InvalidKeyMaterial { context: "encapsulation key must not be empty" });
        }
        Ok(Self(bytes))
    }

    pub fn into_inner(self) -> Vec<u8> {
        self.0
    }
}

impl AsRef<[u8]> for MlkemEncapsulationKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl TryFrom<Vec<u8>> for MlkemEncapsulationKey {
    type Error = CryptoError;
    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        MlkemEncapsulationKey::new(value)
    }
}

/// ML-KEM parameter sets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MlkemSpec {
    MlKem512,
    MlKem768,
    MlKem1024,
}

impl MlkemSpec {
    fn algorithm(&self) -> &'static str {
        match self {
            Self::MlKem512 => "ML-KEM-512",
            Self::MlKem768 => "ML-KEM-768",
            Self::MlKem1024 => "ML-KEM-1024",
        }
    }

    /// Create a decapsulator holding a freshly generated ML-KEM private key.
    pub fn decapsulator(self) -> CryptoResult<MlkemDecapsulator> {
        let dec = ossl::mlkem::MlkemDecapsulation::create(self.algorithm())?;
        Ok(MlkemDecapsulator { spec: self, dec })
    }

    /// Recreate a decapsulator from a serialized private key.
    pub fn decapsulator_from_private_key(self, private_key: MlkemPrivateKey) -> CryptoResult<MlkemDecapsulator> {
        let dec = ossl::mlkem::MlkemDecapsulation::create_from_private_key(self.algorithm(), private_key.as_ref())?;
        Ok(MlkemDecapsulator { spec: self, dec })
    }

    /// Create an encapsulator from a public (encapsulation) key.
    pub fn encapsulator(self, public_key: MlkemEncapsulationKey) -> CryptoResult<MlkemEncapsulator> {
        let enc = ossl::mlkem::MlkemEncapsulation::create(self.algorithm(), public_key.as_ref())?;
        Ok(MlkemEncapsulator { spec: self, enc })
    }
}

/// Encapsulation helper for ML-KEM.
pub struct MlkemEncapsulator {
    spec: MlkemSpec,
    enc: ossl::mlkem::MlkemEncapsulation,
}

impl MlkemEncapsulator {
    /// Perform KEM encapsulation, returning `(wrapped_key, shared_secret)`.
    pub fn encapsulate(&self) -> CryptoResult<(MlkemWrappedKey, MlkemSharedSecret)> {
        let (wrapped, secret) = self.enc.encapsulate()?;
        Ok((MlkemWrappedKey::new(wrapped)?, MlkemSharedSecret::new_secret(secret)))
    }

    pub fn spec(&self) -> &MlkemSpec {
        &self.spec
    }
}

/// Decapsulation helper for ML-KEM.
pub struct MlkemDecapsulator {
    spec: MlkemSpec,
    dec: ossl::mlkem::MlkemDecapsulation,
}

impl MlkemDecapsulator {
    /// Recover the shared secret from a `WrappedKey` produced by encapsulation.
    pub fn decapsulate(&self, wrapped_key: MlkemWrappedKey) -> CryptoResult<MlkemSharedSecret> {
        let secret = self.dec.decapsulate(wrapped_key.as_ref())?;
        Ok(MlkemSharedSecret::new_secret(secret))
    }

    /// Export the public (encapsulation) key corresponding to this decapsulator.
    pub fn public_key(&self) -> CryptoResult<MlkemEncapsulationKey> {
        MlkemEncapsulationKey::new(self.dec.get_encapsulation_key()?)
    }

    /// Export the private key as PKCS#8 DER.
    pub fn export_private_key(&self) -> CryptoResult<MlkemPrivateKey> {
        MlkemPrivateKey::new(self.dec.get_private_key()?)
    }

    pub fn spec(&self) -> &MlkemSpec {
        &self.spec
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(spec: MlkemSpec) {
        let dec = spec.clone().decapsulator().expect("decapsulator");

        let pk = dec.public_key().unwrap();
        let enc = spec.clone().encapsulator(pk).expect("encapsulator");
        assert_eq!(enc.spec(), &spec);
        assert_eq!(dec.spec(), &spec);
        let (wrapped, ss_enc) = enc.encapsulate().expect("encapsulate");

        let ss_dec = dec.decapsulate(wrapped).expect("decapsulate");

        // Shared secret must match
        assert_eq!(ss_enc.as_ref(), ss_dec.as_ref(), "shared secret equality");

        // Import decapsulator from exported private key
        let exported = dec.export_private_key().expect("export pk");
        let dec2 = spec.clone().decapsulator_from_private_key(exported).expect("decapsulator from pk");
        assert_eq!(dec2.spec(), &spec);
        let (wrapped2, ss_enc2) = enc.encapsulate().expect("encapsulate with imported decapsulator");
        let ss_dec2 = dec2.decapsulate(wrapped2).expect("decapsulate imported");
        assert_eq!(ss_enc2.as_ref(), ss_dec2.as_ref(), "imported decapsulator yields same secret");
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

    #[test]
    fn key_wrappers_reject_empty_bytes() {
        assert!(matches!(MlkemPrivateKey::new(Vec::new()), Err(CryptoError::InvalidKeyMaterial { .. })));
        assert!(matches!(MlkemWrappedKey::new(Vec::new()), Err(CryptoError::InvalidKeyMaterial { .. })));
        assert!(matches!(MlkemEncapsulationKey::new(Vec::new()), Err(CryptoError::InvalidKeyMaterial { .. })));
    }
}
