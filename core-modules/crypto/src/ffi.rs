// SPDX-FileCopyrightText: Copyright 2026 gematik GmbH
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

use crate::error::CryptoError as CoreCryptoError;
use crate::exchange::elc::generate_elc_ephemeral_public_key_from_cvc;
use thiserror::Error;

/// UniFFI-friendly error type for exported crypto helpers.
#[derive(Debug, Clone, Error)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Error))]
pub enum CryptoError {
    #[error("invalid argument: {reason}")]
    InvalidArgument { reason: String },
    #[error("ASN.1 decode error: {reason}")]
    Asn1Decode { reason: String },
    #[error("crypto error: {reason}")]
    Crypto { reason: String },
}

impl From<CoreCryptoError> for CryptoError {
    fn from(err: CoreCryptoError) -> Self {
        match err {
            CoreCryptoError::Asn1Decoding(inner) => Self::Asn1Decode { reason: inner.to_string() },
            CoreCryptoError::InvalidEcPoint(reason) => Self::InvalidArgument { reason },
            CoreCryptoError::InvalidKeyMaterial { context } => Self::InvalidArgument { reason: context.to_owned() },
            CoreCryptoError::InvalidKeyLength { expected, actual } => Self::InvalidArgument {
                reason: format!("invalid key length: expected one of {expected:?}, got {actual}"),
            },
            CoreCryptoError::InvalidIvLength { mode, expected, actual } => Self::InvalidArgument {
                reason: format!("invalid {mode} IV/nonce length: expected one of {expected:?}, got {actual}"),
            },
            CoreCryptoError::InvalidTagLength { expected_min, expected_max, actual } => Self::InvalidArgument {
                reason: format!(
                    "invalid AEAD tag length: expected between {expected_min} and {expected_max}, got {actual}"
                ),
            },
            other => Self::Crypto { reason: other.to_string() },
        }
    }
}

/// Generates the host-side ephemeral public key for ELC from the supplied end-entity CVC.
#[uniffi::export]
pub fn generate_elc_ephemeral_public_key(cvc: Vec<u8>) -> Result<Vec<u8>, CryptoError> {
    generate_elc_ephemeral_public_key_from_cvc(&cvc).map_err(CryptoError::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    fn load_fixture(name: &str) -> Vec<u8> {
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.pop();
        path.pop();
        path.push("test-vectors");
        path.push("cvc-chain");
        path.push("pki_cvc_g2_input");
        path.push("Atos_CVC-Root-CA");
        path.push(name);
        fs::read(&path).expect("fixture should be readable")
    }

    #[test]
    fn generate_elc_ephemeral_public_key_exports_public_key_bytes() {
        let cvc_bytes = load_fixture("DEGXX820214.cvc");

        let pk = generate_elc_ephemeral_public_key(cvc_bytes).expect("key generation succeeds");

        assert!(!pk.is_empty());
    }

    #[test]
    fn generate_elc_ephemeral_public_key_rejects_invalid_input() {
        let result = generate_elc_ephemeral_public_key(Vec::new());

        assert!(matches!(result, Err(CryptoError::Asn1Decode { .. })));
    }
}
