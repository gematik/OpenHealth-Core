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

use crate::key::ec_key::{EcCurve, EcPrivateKey, EcPublicKey};

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
    private_key: &EcPrivateKey,
) -> Box<dyn Ecdh> {
    unimplemented!()
}

// #[cfg(test)]
// mod tests {
//     use super::*;
//     use crate::utils::test_utils::{hex_to_bytes, to_hex_string};
//
//     const EC_PUBLIC_KEY_PEM: &str = r#"-----BEGIN PUBLIC KEY-----
// MFowFAYHKoZIzj0CAQYJKyQDAwIIAQEHA0IABJBhNcQG6SALcDA4AOUgfySk4E0o
// LGTt+qP6dgv9qYMtojIMVQKNWfT14xR7LQnoSPABZlLJmWgh2cYKz3WbpVM=
// -----END PUBLIC KEY-----"#;
//
//     const EC_PRIVATE_KEY_PEM: &str = r#"-----BEGIN EC PRIVATE KEY-----
// MIGIAgEAMBQGByqGSM49AgEGCSskAwMCCAEBBwRtMGsCAQEEIBu09g2V3coZsiK7
// AUT8gHFehP7KK77g83GJH2aeYxJ1oUQDQgAEkGE1xAbpIAtwMDgA5SB/JKTgTSgs
// ZO36o/p2C/2pgy2iMgxVAo1Z9PXjFHstCehI8AFmUsmZaCHZxgrPdZulUw==
// -----END EC PRIVATE KEY-----"#;
//
//     #[test]
//     fn compute_secret() {
//         let public_key = EcPublicKey::decode_from_pem(EC_PUBLIC_KEY_PEM).unwrap();
//         let private_key = EcPrivateKey::decode_from_pem(EC_PRIVATE_KEY_PEM).unwrap();
//
//         let result = EcdhSpec {
//             curve: EcCurve::BrainpoolP256r1,
//         }
//             .create_key_exchange(&private_key)
//             .compute_secret(&public_key);
//
//         assert_eq!(
//             to_hex_string(&result),
//             "A6 00 6D F4 D0 9A A6 B7 AF 41 B8 FF E6 62 78 CE B2 F6 B8 44 E1 6F 1A 73 F3 3E CB EA D3 AF 0A 7B"
//         );
//     }
// }