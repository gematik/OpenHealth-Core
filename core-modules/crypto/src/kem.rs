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
use crate::key::SecretKey;
use crate::ossl;
use crate::utils::byte_unit::{ByteUnit, BytesExt};
use zeroize::Zeroizing;

struct MlkemSecret;

pub type MlkemSharedSecret = SecretKey;
pub type MlkemWrappedKey = Vec<u8>;
pub type MlkemEncapsulationKey = Vec<u8>;

/// ML-KEM parameter sets.
#[derive(Debug, Clone)]
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
        Ok((MlkemWrappedKey::from(wrapped), MlkemSharedSecret::new_secret(secret)))
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
        Ok(self.dec.get_encapsulation_key()?)
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
        assert_eq!(ss_enc.as_ref(), ss_dec.as_ref(), "shared secret equality");
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
