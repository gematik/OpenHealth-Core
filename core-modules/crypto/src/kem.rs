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

use crate::error::CryptoResult;
use crate::key::key::{KeySize, PublicKey};
use crate::ossl;
use crate::utils::byte_unit::{ByteUnit, BytesExt};

/// Wrapped KEM ciphertext returned by encapsulation.
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct WrappedKey(Vec<u8>);

impl AsRef<[u8]> for WrappedKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl KeySize for WrappedKey {
    fn size(&self) -> ByteUnit {
        self.0.len().bytes()
    }
}

/// Shared secret derived from ML-KEM operations.
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct SharedSecret(Vec<u8>);

impl SharedSecret {
    /// Create a shared secret from raw bytes.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
impl SharedSecret {
    #[cfg_attr(feature = "uniffi", uniffi::constructor)]
    /// Construct a shared secret from bytes (UniFFI-friendly constructor).
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Return the secret bytes.
    pub fn as_bytes(&self) -> Vec<u8> {
        self.0.clone()
    }
}

/// ML-KEM parameter sets.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
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

    /// Create an encapsulator from a public (encapsulation) key.
    pub fn encapsulator(self, public_key: PublicKey) -> CryptoResult<MlkemEncapsulator> {
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
    pub fn encapsulate(&self) -> CryptoResult<(WrappedKey, SharedSecret)> {
        let (wrapped, secret) = self.enc.encapsulate()?;
        Ok((WrappedKey(wrapped), SharedSecret(secret)))
    }
}

/// Decapsulation helper for ML-KEM.
pub struct MlkemDecapsulator {
    spec: MlkemSpec,
    dec: ossl::mlkem::MlkemDecapsulation,
}

impl MlkemDecapsulator {
    /// Recover the shared secret from a `WrappedKey` produced by encapsulation.
    pub fn decapsulate(&self, wrapped_key: WrappedKey) -> CryptoResult<SharedSecret> {
        let secret = self.dec.decapsulate(wrapped_key.as_ref())?;
        Ok(SharedSecret::new(secret))
    }

    /// Export the public (encapsulation) key corresponding to this decapsulator.
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
        assert_eq!(
            ss_enc.as_bytes(),
            ss_dec.as_bytes(),
            "shared secret equality"
        );
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
