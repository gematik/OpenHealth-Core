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

use crate::ec::ec_key::{EcCurve, EcKeyPairSpec, EcPrivateKey, EcPublicKey};
use crate::error::CryptoError as CoreCryptoError;
use crate::exchange::ecdh::Ecdh;
use crate::key::SecretKey;
use crate::mac::{CmacAlgorithm, MacSpec};
use openhealth_asn1::cv_certificate::parse_cv_certificate;
use std::sync::Arc;
use thiserror::Error;

const TAG_CVC_PUBLIC_POINT: u8 = 0x86;
const BRAINPOOL_P256R1_PUBLIC_KEY_LEN: usize = 65;

#[derive(Debug, Clone, Error)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Error))]
pub enum CryptoException {
    #[error("invalid argument: {reason}")]
    InvalidArgument { reason: String },
    #[error("ASN.1 decode error: {reason}")]
    Asn1Decode { reason: String },
    #[error("crypto error: {reason}")]
    Crypto { reason: String },
}

impl From<CoreCryptoError> for CryptoException {
    fn from(error: CoreCryptoError) -> Self {
        match error {
            CoreCryptoError::Asn1Decoding(inner) => Self::Asn1Decode { reason: inner.to_string() },
            other => Self::Crypto { reason: other.to_string() },
        }
    }
}

#[derive(uniffi::Object)]
pub struct BrainpoolP256r1KeyPair {
    private_key: SecretKey,
    public_key: Vec<u8>,
}

#[uniffi::export]
impl BrainpoolP256r1KeyPair {
    pub fn private_key(&self) -> Vec<u8> {
        self.private_key.as_ref().to_vec()
    }

    pub fn public_key(&self) -> Vec<u8> {
        self.public_key.clone()
    }
}

/// Generates the host-side ephemeral public key for ELC from the supplied end-entity CVC.
#[uniffi::export]
pub fn generate_elc_ephemeral_public_key(cvc: Vec<u8>) -> Result<Vec<u8>, CryptoException> {
    extract_cvc_brainpool_p256r1_public_key(&cvc)
}

/// Generates a fresh brainpoolP256r1 EC key pair and returns raw key bytes.
#[uniffi::export]
pub fn generate_brainpool_p256r1_key_pair() -> Result<Arc<BrainpoolP256r1KeyPair>, CryptoException> {
    let (public_key, private_key) =
        EcKeyPairSpec { curve: EcCurve::BrainpoolP256r1 }.generate_keypair().map_err(CryptoException::from)?;
    Ok(Arc::new(BrainpoolP256r1KeyPair {
        private_key: SecretKey::new_secret(private_key.as_bytes().to_vec()),
        public_key: public_key.as_bytes().to_vec(),
    }))
}

/// Derives the raw ECDH shared secret on brainpoolP256r1 from raw private/public key bytes.
#[uniffi::export]
pub fn brainpool_p256r1_ecdh(private_key: Vec<u8>, peer_public_key: Vec<u8>) -> Result<Vec<u8>, CryptoException> {
    if private_key.is_empty() {
        return Err(CryptoException::InvalidArgument { reason: "private key must not be empty".to_string() });
    }
    let private_key = EcPrivateKey::from_bytes(EcCurve::BrainpoolP256r1, private_key);
    let peer_public_key =
        EcPublicKey::from_uncompressed(EcCurve::BrainpoolP256r1, peer_public_key).map_err(CryptoException::from)?;
    let shared_secret =
        Ecdh::new(private_key).and_then(|ecdh| ecdh.derive(peer_public_key)).map_err(CryptoException::from)?;
    Ok(shared_secret.as_ref().to_vec())
}

/// Computes AES-CMAC and returns the requested number of leading tag bytes.
#[uniffi::export]
pub fn aes_cmac(key: Vec<u8>, message: Vec<u8>, output_length: i32) -> Result<Vec<u8>, CryptoException> {
    let mut mac = MacSpec::Cmac { algorithm: CmacAlgorithm::Aes }
        .create(SecretKey::new_secret(key))
        .map_err(CryptoException::from)?;
    mac.update(&message).map_err(CryptoException::from)?;
    let tag = mac.finalize().map_err(CryptoException::from)?;
    let output_length = usize::try_from(output_length).map_err(|_| CryptoException::InvalidArgument {
        reason: "requested CMAC output length must not be negative".to_string(),
    })?;
    if output_length > tag.len() {
        return Err(CryptoException::InvalidArgument {
            reason: format!("requested CMAC output length {output_length} exceeds tag length {}", tag.len()),
        });
    }
    Ok(tag[..output_length].to_vec())
}

fn extract_cvc_brainpool_p256r1_public_key(cvc: &[u8]) -> Result<Vec<u8>, CryptoException> {
    let certificate =
        parse_cv_certificate(cvc).map_err(|err| CryptoException::Asn1Decode { reason: err.to_string() })?;
    let public_key = extract_single_byte_tag_value(&certificate.body.public_key.key_data, TAG_CVC_PUBLIC_POINT)?;
    if public_key.len() != BRAINPOOL_P256R1_PUBLIC_KEY_LEN || public_key.first() != Some(&0x04) {
        return Err(CryptoException::InvalidArgument {
            reason: "CVC does not contain a valid uncompressed brainpoolP256r1 public key".to_string(),
        });
    }
    Ok(public_key)
}

fn extract_single_byte_tag_value(data: &[u8], expected_tag: u8) -> Result<Vec<u8>, CryptoException> {
    let mut offset = 0usize;
    while offset < data.len() {
        let tag = data[offset];
        offset += 1;

        let (len, len_octets) = parse_definite_length(&data[offset..])?;
        offset += len_octets;

        let end = offset
            .checked_add(len)
            .ok_or_else(|| CryptoException::InvalidArgument { reason: "TLV length overflow".to_string() })?;
        if end > data.len() {
            return Err(CryptoException::InvalidArgument { reason: "TLV value exceeds input length".to_string() });
        }

        if tag == expected_tag {
            return Ok(data[offset..end].to_vec());
        }
        offset = end;
    }

    Err(CryptoException::InvalidArgument { reason: format!("missing TLV tag 0x{expected_tag:02X}") })
}

fn parse_definite_length(data: &[u8]) -> Result<(usize, usize), CryptoException> {
    let first =
        *data.first().ok_or_else(|| CryptoException::InvalidArgument { reason: "missing TLV length".to_string() })?;
    if (first & 0x80) == 0 {
        return Ok((first as usize, 1));
    }

    let count = (first & 0x7F) as usize;
    if count == 0 {
        return Err(CryptoException::InvalidArgument { reason: "indefinite lengths are not supported".to_string() });
    }
    if count > std::mem::size_of::<usize>() {
        return Err(CryptoException::InvalidArgument { reason: "TLV length uses too many octets".to_string() });
    }
    if data.len() < 1 + count {
        return Err(CryptoException::InvalidArgument { reason: "truncated TLV length".to_string() });
    }

    let mut len = 0usize;
    for byte in &data[1..=count] {
        len = len
            .checked_mul(256)
            .and_then(|value| value.checked_add(*byte as usize))
            .ok_or_else(|| CryptoException::InvalidArgument { reason: "TLV length overflow".to_string() })?;
    }
    Ok((len, 1 + count))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_to_bytes(hex_str: &str) -> Vec<u8> {
        hex::decode(hex_str.replace(char::is_whitespace, "")).unwrap()
    }

    #[test]
    fn generate_elc_ephemeral_public_key_extracts_cvc_public_point() {
        let cvc = hex_to_bytes(
            "\
            7f2181da7f4e81935f290170420844454758581102237f494b06062b24030503\
            018641045e7ae614740e7012e350de71c10021ec668f21d6859591b4f709c4c7\
            3cce91c5a7fb0be1327e59ff1d0cb402b9c2bb0dc0432fa566bd4ff5f532258c\
            7364aecd5f200c0009802768831100001565497f4c1306082a8214004c048118\
            5307000000000000005f25060204000400025f24060209000400015f37409d24\
            4d497832172304f298bd49f91f45bf346cb306adeb44b0742017a074902146cc\
            cbdbb35426c2eb602d38253d92ebe1ac6905f388407398a474c4ea612d84",
        );

        let public_key = generate_elc_ephemeral_public_key(cvc).unwrap();

        assert_eq!(public_key.len(), BRAINPOOL_P256R1_PUBLIC_KEY_LEN);
        assert_eq!(
            hex::encode(public_key),
            concat!(
                "045e7ae614740e7012e350de71c10021ec668f21d6859591b4f709c4c73cce91",
                "c5a7fb0be1327e59ff1d0cb402b9c2bb0dc0432fa566bd4ff5f532258c7364aecd"
            )
        );
    }

    #[test]
    fn brainpool_p256r1_ecdh_matches_for_both_sides() {
        let left = generate_brainpool_p256r1_key_pair().unwrap();
        let right = generate_brainpool_p256r1_key_pair().unwrap();

        let left_secret = brainpool_p256r1_ecdh(left.private_key(), right.public_key()).unwrap();
        let right_secret = brainpool_p256r1_ecdh(right.private_key(), left.public_key()).unwrap();

        assert_eq!(left_secret, right_secret);
        assert!(!left_secret.is_empty());
    }

    #[test]
    fn aes_cmac_truncates_to_requested_length() {
        let tag = aes_cmac(
            hex_to_bytes("2B7E151628AED2A6ABF7158809CF4F3C"),
            hex_to_bytes("6BC1BEE22E409F96E93D7E117393172A"),
            8,
        )
        .unwrap();

        assert_eq!(hex::encode(tag), "070a16b46b4d4144");
    }
}
