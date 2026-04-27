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

use crate::cvc as core_cvc;
use crate::ec::ec_key::{EcCurve, EcKeyPairSpec, EcPrivateKey, EcPublicKey};
use crate::error::CryptoError as CoreCryptoError;
use crate::exchange::ecdh::Ecdh;
use crate::exchange::elc::generate_elc_ephemeral_public_key_from_cvc;
use crate::key::SecretKey;
use crate::mac::{CmacAlgorithm, MacSpec};
use openhealth_asn1::ffi::CvCertificate;
use std::sync::Arc;
use std::time::SystemTime;
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
            CoreCryptoError::InvalidCvcChain { context } => Self::InvalidArgument { reason: context },
            CoreCryptoError::InvalidCvcSignature { context } => Self::Crypto { reason: context },
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

#[derive(uniffi::Object)]
pub struct BrainpoolP256r1KeyPair {
    private_key: SecretKey,
    public_key: Vec<u8>,
}

#[derive(uniffi::Object)]
pub struct CvcTrustAnchor {
    inner: core_cvc::CvcTrustAnchor,
}

#[uniffi::export]
impl CvcTrustAnchor {
    #[uniffi::constructor]
    pub fn from_certificate(certificate: Arc<CvCertificate>) -> Result<Arc<Self>, CryptoError> {
        let inner = core_cvc::CvcTrustAnchor::from_certificate(certificate.as_core()).map_err(CryptoError::from)?;
        Ok(Arc::new(Self { inner }))
    }

    #[uniffi::constructor]
    pub fn from_public_key_tlv(reference: Vec<u8>, public_key_tlv: Vec<u8>) -> Result<Arc<Self>, CryptoError> {
        let inner =
            core_cvc::CvcTrustAnchor::from_public_key_tlv(reference, &public_key_tlv).map_err(CryptoError::from)?;
        Ok(Arc::new(Self { inner }))
    }

    pub fn reference(&self) -> Vec<u8> {
        self.inner.reference().to_vec()
    }
}

#[derive(uniffi::Object)]
pub struct CvcChainValidationResult {
    inner: core_cvc::CvcChainValidationResult,
}

#[uniffi::export]
impl CvcChainValidationResult {
    pub fn validated_certificates(&self) -> u64 {
        self.inner.validated_certificates() as u64
    }

    pub fn end_entity_chr(&self) -> Vec<u8> {
        self.inner.end_entity_chr().to_vec()
    }
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
pub fn generate_elc_ephemeral_public_key(cvc: Vec<u8>) -> Result<Vec<u8>, CryptoError> {
    generate_elc_ephemeral_public_key_from_cvc(&cvc).map_err(CryptoError::from)
}

#[uniffi::export]
pub fn validate_cvc_chain(
    chain: Vec<Arc<CvCertificate>>,
    trust_anchors: Vec<Arc<CvcTrustAnchor>>,
    validation_time: SystemTime,
) -> Result<Arc<CvcChainValidationResult>, CryptoError> {
    let chain = chain.iter().map(|certificate| certificate.as_core().clone()).collect::<Vec<_>>();
    let trust_anchors = trust_anchors.iter().map(|anchor| anchor.inner.clone()).collect::<Vec<_>>();
    let inner = core_cvc::validate_cvc_chain(&chain, &trust_anchors, validation_time).map_err(CryptoError::from)?;
    Ok(Arc::new(CvcChainValidationResult { inner }))
}

/// Generates a fresh brainpoolP256r1 EC key pair and returns raw key bytes.
#[uniffi::export]
pub fn generate_brainpool_p256r1_key_pair() -> Result<Arc<BrainpoolP256r1KeyPair>, CryptoError> {
    let (public_key, private_key) =
        EcKeyPairSpec { curve: EcCurve::BrainpoolP256r1 }.generate_keypair().map_err(CryptoError::from)?;
    Ok(Arc::new(BrainpoolP256r1KeyPair {
        private_key: SecretKey::new_secret(private_key.as_bytes().to_vec()),
        public_key: public_key.as_bytes().to_vec(),
    }))
}

/// Derives the raw ECDH shared secret on brainpoolP256r1 from raw private/public key bytes.
#[uniffi::export]
pub fn brainpool_p256r1_ecdh(private_key: Vec<u8>, peer_public_key: Vec<u8>) -> Result<Vec<u8>, CryptoError> {
    if private_key.is_empty() {
        return Err(CryptoError::InvalidArgument { reason: "private key must not be empty".to_string() });
    }

    let private_key = EcPrivateKey::from_bytes(EcCurve::BrainpoolP256r1, private_key);
    let peer_public_key =
        EcPublicKey::from_uncompressed(EcCurve::BrainpoolP256r1, peer_public_key).map_err(CryptoError::from)?;
    let shared_secret =
        Ecdh::new(private_key).and_then(|ecdh| ecdh.derive(peer_public_key)).map_err(CryptoError::from)?;
    Ok(shared_secret.as_ref().to_vec())
}

/// Computes AES-CMAC and returns the requested number of leading tag bytes.
#[uniffi::export]
pub fn aes_cmac(key: Vec<u8>, message: Vec<u8>, output_length: i32) -> Result<Vec<u8>, CryptoError> {
    let mut mac = MacSpec::Cmac { algorithm: CmacAlgorithm::Aes }
        .create(SecretKey::new_secret(key))
        .map_err(CryptoError::from)?;
    mac.update(&message).map_err(CryptoError::from)?;
    let tag = mac.finalize().map_err(CryptoError::from)?;
    let output_length = usize::try_from(output_length).map_err(|_| CryptoError::InvalidArgument {
        reason: "requested CMAC output length must not be negative".to_string(),
    })?;
    if output_length > tag.len() {
        return Err(CryptoError::InvalidArgument {
            reason: format!("requested CMAC output length {output_length} exceeds tag length {}", tag.len()),
        });
    }
    Ok(tag[..output_length].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use std::fs;
    use std::path::PathBuf;

    fn hex_to_bytes(hex_str: &str) -> Vec<u8> {
        hex::decode(hex_str.replace(char::is_whitespace, "")).unwrap()
    }

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

    fn load_trust_anchor(name: &str) -> Vec<u8> {
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.pop();
        path.pop();
        path.push("test-vectors");
        path.push("cvc-chain");
        path.push("pki_cvc_g2_input");
        path.push("trust-anchor");
        path.push(name);
        fs::read(&path).expect("fixture should be readable")
    }

    fn validation_time(year: i32, month: u32, day: u32) -> SystemTime {
        chrono::Utc.with_ymd_and_hms(year, month, day, 12, 0, 0).single().unwrap().into()
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

    #[test]
    fn validate_cvc_chain_accepts_asn1_cvc_objects() {
        let cvc = openhealth_asn1::ffi::parse_cv_certificate(load_fixture("DEGXX820214.cvc")).unwrap();
        let anchor = CvcTrustAnchor::from_public_key_tlv(
            hex_to_bytes("4445475858820214"),
            load_trust_anchor("4445475858820214_ELC-PublicKey.der"),
        )
        .unwrap();

        let result = validate_cvc_chain(vec![cvc], vec![anchor], validation_time(2020, 1, 1)).unwrap();

        assert_eq!(result.validated_certificates(), 1);
        assert_eq!(hex::encode(result.end_entity_chr()), "4445475858820214");
    }

    #[test]
    fn cvc_trust_anchor_from_certificate_uses_holder_reference() {
        let cvc = openhealth_asn1::ffi::parse_cv_certificate(load_fixture("DEGXX820214.cvc")).unwrap();

        let anchor = CvcTrustAnchor::from_certificate(cvc).unwrap();

        assert_eq!(hex::encode(anchor.reference()), "4445475858820214");
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
