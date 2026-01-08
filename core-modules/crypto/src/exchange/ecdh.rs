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

use crate::ec::ec_key::{EcPrivateKey, EcPublicKey};
use crate::error::CryptoResult;
use crate::key::SecretKey;
use crate::ossl;

pub type EcdhSharedSecret = SecretKey;

/// ECDH context for deriving shared secrets.
///
/// Construct from a private key (DER PKCS#8), then call `derive` with a peer
/// public key (DER SubjectPublicKeyInfo) to compute the raw ECDH shared secret.
pub struct Ecdh {
    ctx: ossl::ec::Ecdh,
}

impl Ecdh {
    /// Create a new ECDH context from a private key in DER (PKCS#8) form.
    pub fn new(private_key: EcPrivateKey) -> CryptoResult<Self> {
        let ctx = ossl::ec::Ecdh::new(private_key.encode_to_asn1()?.as_ref())?;
        Ok(Self { ctx })
    }

    /// Derive the ECDH shared secret from the peer's public key (DER SPKI).
    pub fn derive(&self, peer_public_key: EcPublicKey) -> CryptoResult<EcdhSharedSecret> {
        let secret = self.ctx.compute_secret(peer_public_key.encode_to_asn1()?.as_ref())?;
        Ok(EcdhSharedSecret::new_secret(secret))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ec::ec_key::{EcCurve, EcKeyPairSpec};

    fn roundtrip(spec: EcKeyPairSpec) {
        let (a_pub, a_priv) = spec.generate_keypair().expect("keypair a");
        let (b_pub, b_priv) = spec.generate_keypair().expect("keypair b");

        let a = Ecdh::new(a_priv).expect("ecdh a");
        let b = Ecdh::new(b_priv).expect("ecdh b");

        let secret_ab = a.derive(b_pub).expect("derive A with B");
        let secret_ba = b.derive(a_pub).expect("derive B with A");

        let s_ab = secret_ab.as_ref();
        let s_ba = secret_ba.as_ref();

        assert_eq!(s_ab, s_ba, "shared secret equality");
        assert!(!s_ab.is_empty());
    }

    #[test]
    fn ecdh_roundtrip_bp256() {
        roundtrip(EcKeyPairSpec { curve: EcCurve::BrainpoolP256r1 });
    }

    #[test]
    fn ecdh_roundtrip_bp384() {
        roundtrip(EcKeyPairSpec { curve: EcCurve::BrainpoolP384r1 });
    }

    #[test]
    fn ecdh_roundtrip_bp512() {
        roundtrip(EcKeyPairSpec { curve: EcCurve::BrainpoolP512r1 });
    }
}
