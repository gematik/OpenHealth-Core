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

use crate::ec::ec_key::EcCurve;
use crate::error::CryptoResult;
use crate::key::{KeyMaterial, PrivateKey, PublicKey};
use crate::ossl;
use zeroize::Zeroizing;

struct EcdhSecret;
impl crate::key::Role for EcdhSecret {}

pub type EcdhSharedSecret = KeyMaterial<EcdhSecret, Zeroizing<Vec<u8>>>;

/// ECDH curves supported at the high level.
#[derive(Clone, Debug)]
pub struct EcdhSpec {
    pub curve: EcCurve,
}

impl EcdhSpec {
    /// Generate a fresh ECDH keypair for this curve.
    pub fn generate_keypair(&self) -> CryptoResult<(PrivateKey, PublicKey)> {
        let keypair = ossl::ec::EcKeypair::generate(self.curve.name())?;
        let priv_der = keypair.private_key_der()?;
        let pub_der = keypair.public_key_der()?;
        Ok((PrivateKey::new_secret(priv_der), PublicKey::new(pub_der)))
    }
}

/// ECDH context for deriving shared secrets.
///
/// Construct from a private key (DER PKCS#8), then call `derive` with a peer
/// public key (DER SubjectPublicKeyInfo) to compute the raw ECDH shared secret.
pub struct Ecdh {
    ctx: ossl::ec::Ecdh,
    pkey: PrivateKey,
}

impl Ecdh {
    /// Create a new ECDH context from a private key in DER (PKCS#8) form.
    pub fn new(private_key: PrivateKey) -> CryptoResult<Self> {
        let ctx = ossl::ec::Ecdh::new(private_key.as_ref())?;
        Ok(Self { ctx, pkey: private_key })
    }

    /// Derive the ECDH shared secret from the peer's public key (DER SPKI).
    pub fn derive(&self, peer_public_key: PublicKey) -> CryptoResult<EcdhSharedSecret> {
        let secret = self.ctx.compute_secret(peer_public_key.as_ref())?;
        Ok(EcdhSharedSecret::new_secret(secret))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(spec: EcdhSpec) {
        let (a_priv, a_pub) = spec.generate_keypair().expect("keypair a");
        let (b_priv, b_pub) = spec.generate_keypair().expect("keypair b");

        let a = Ecdh::new(a_priv).expect("ecdh a");
        let b = Ecdh::new(b_priv).expect("ecdh b");

        let secret_ab = a.derive(b_pub).expect("derive A with B");
        let secret_ba = b.derive(a_pub).expect("derive B with A");

        let s_ab = secret_ab.as_bytes();
        let s_ba = secret_ba.as_bytes();

        assert_eq!(s_ab, s_ba, "shared secret equality");
        assert!(s_ab.len() > 0);
    }

    #[test]
    fn ecdh_roundtrip_bp256() {
        roundtrip(EcdhSpec { curve: EcCurve::BrainpoolP256r1 });
    }

    #[test]
    fn ecdh_roundtrip_bp384() {
        roundtrip(EcdhSpec { curve: EcCurve::BrainpoolP384r1 });
    }

    #[test]
    fn ecdh_roundtrip_bp512() {
        roundtrip(EcdhSpec { curve: EcCurve::BrainpoolP512r1 });
    }
}
