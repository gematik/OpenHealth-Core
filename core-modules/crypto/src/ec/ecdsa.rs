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

use crate::digest::DigestSpec;
use crate::ec::ec_key::{EcCurve, EcPublicKey};
use crate::error::{CryptoError, CryptoResult};

fn curve_for_brainpool_public_key(public_key: &[u8]) -> CryptoResult<EcCurve> {
    match public_key.len() {
        65 => Ok(EcCurve::BrainpoolP256r1),
        97 => Ok(EcCurve::BrainpoolP384r1),
        129 => Ok(EcCurve::BrainpoolP512r1),
        _ => Err(CryptoError::InvalidEcPoint(format!(
            "unsupported uncompressed brainpool public key length {}",
            public_key.len()
        ))),
    }
}

fn coordinate_size(curve: &EcCurve) -> usize {
    match curve {
        EcCurve::BrainpoolP256r1 => 32,
        EcCurve::BrainpoolP384r1 => 48,
        EcCurve::BrainpoolP512r1 => 64,
    }
}

fn hash_message(curve: &EcCurve, message: &[u8]) -> CryptoResult<Vec<u8>> {
    let spec = match curve {
        EcCurve::BrainpoolP256r1 => DigestSpec::Sha256,
        EcCurve::BrainpoolP384r1 => DigestSpec::Sha384,
        EcCurve::BrainpoolP512r1 => DigestSpec::Sha512,
    };
    let mut digest = spec.create()?;
    digest.update(message)?;
    digest.finalize()
}

pub(crate) fn decode_ec_public_key(public_key: &[u8]) -> CryptoResult<EcPublicKey> {
    let curve = curve_for_brainpool_public_key(public_key)?;
    EcPublicKey::from_uncompressed(curve, public_key)
}

fn verify_signature_value(public_key: &EcPublicKey, value: &[u8], signature: &[u8]) -> CryptoResult<bool> {
    let expected_signature_len = coordinate_size(public_key.curve()) * 2;
    if signature.len() != expected_signature_len {
        return Err(CryptoError::InvalidSignatureLength { expected: expected_signature_len, actual: signature.len() });
    }

    let public_key_der = public_key.encode_to_asn1()?;
    crate::ossl::ec::verify_ecdsa(public_key_der.as_ref(), value, signature).map_err(Into::into)
}

/// Verifies a raw ECDSA signature over the supplied message.
///
/// The message is hashed with the SHA-2 variant implied by the public key curve.
pub fn verify_ecdsa_message(public_key: &EcPublicKey, message: &[u8], signature: &[u8]) -> CryptoResult<bool> {
    let digest = hash_message(public_key.curve(), message)?;
    verify_signature_value(public_key, &digest, signature)
}

/// Verifies a raw ECDSA signature against a caller-supplied big-endian verification value.
pub fn verify_ecdsa_value(public_key: &EcPublicKey, value: &[u8], signature: &[u8]) -> CryptoResult<bool> {
    verify_signature_value(public_key, value, signature)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PUBLIC_KEY: &str =
        "04223ddca232b0188e6aa70f8d8beb5e67347b8b0d759c7f361a1930cfdc3571b02e59ef95e567076bff633922ae6d97514a771188171b2aa1603455d0031c168a";
    const MESSAGE: &[u8] = b"OpenHealth brainpool verify test";
    const MESSAGE_DIGEST_SHA256: &str = "aade9d5d08b880411fa7c2bff4d8af93cd43fa942fe9d3b2377121328be5cbc7";
    const SIGNATURE: &str =
        "96c713abe48f06e0f6cde0709501268302ee7a41b4d2b188e661fe86bfe832084e11b5995ca4fd152efa1045e573026ead3e7accb0cd4e634ddc45e6ac804fe2";

    fn hex_to_bytes(value: &str) -> Vec<u8> {
        hex::decode(value).unwrap()
    }

    #[test]
    fn verify_message_accepts_valid_signature() {
        let public_key = decode_ec_public_key(&hex_to_bytes(PUBLIC_KEY)).unwrap();
        let valid = verify_ecdsa_message(&public_key, MESSAGE, &hex_to_bytes(SIGNATURE)).unwrap();

        assert!(valid);
    }

    #[test]
    fn verify_value_accepts_valid_signature_for_digest_input() {
        let public_key = decode_ec_public_key(&hex_to_bytes(PUBLIC_KEY)).unwrap();
        let valid =
            verify_ecdsa_value(&public_key, &hex_to_bytes(MESSAGE_DIGEST_SHA256), &hex_to_bytes(SIGNATURE)).unwrap();

        assert!(valid);
    }

    #[test]
    fn verify_message_rejects_modified_signature() {
        let public_key = decode_ec_public_key(&hex_to_bytes(PUBLIC_KEY)).unwrap();
        let mut signature = hex_to_bytes(SIGNATURE);
        signature[0] ^= 0x01;

        let valid = verify_ecdsa_message(&public_key, MESSAGE, &signature).unwrap();

        assert!(!valid);
    }

    #[test]
    fn verify_value_rejects_invalid_signature_length() {
        let public_key = decode_ec_public_key(&hex_to_bytes(PUBLIC_KEY)).unwrap();
        let err = verify_ecdsa_value(&public_key, &hex_to_bytes(MESSAGE_DIGEST_SHA256), &[0x01; 63]).unwrap_err();

        assert!(matches!(err, CryptoError::InvalidSignatureLength { expected: 64, actual: 63 }));
    }
}
