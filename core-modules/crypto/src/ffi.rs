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
use crate::ec::ecdsa::{verify_brainpool_ecdsa_message, verify_brainpool_ecdsa_value};
use crate::error::CryptoError as CoreCryptoError;
use crate::exchange::ecdh::Ecdh;
use crate::exchange::elc::generate_elc_ephemeral_public_key_from_cvc;
use crate::key::SecretKey;
use crate::mac::{CmacAlgorithm, MacSpec};
use num_bigint::{BigInt, Sign};
use openhealth_asn1::cv_certificate::CvCertificate as ParsedCvCertificate;
use std::sync::Arc;
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
            CoreCryptoError::InvalidSignatureLength { expected, actual } => Self::InvalidArgument {
                reason: format!("invalid ECDSA signature length: expected {expected}, got {actual}"),
            },
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

/// Verifies a raw brainpool ECDSA signature over a message, hashing with the SHA-2 variant implied by the curve size.
#[uniffi::export]
pub fn verify_brainpool_ecdsa_message_signature(
    public_key: Vec<u8>,
    message: Vec<u8>,
    signature: Vec<u8>,
) -> Result<bool, CryptoError> {
    verify_brainpool_ecdsa_message(&public_key, &message, &signature).map_err(CryptoError::from)
}

/// Verifies a raw brainpool ECDSA signature against the supplied big-endian verification value without hashing it first.
#[uniffi::export]
pub fn verify_brainpool_ecdsa_value_signature(
    public_key: Vec<u8>,
    value: Vec<u8>,
    signature: Vec<u8>,
) -> Result<bool, CryptoError> {
    verify_brainpool_ecdsa_value(&public_key, &value, &signature).map_err(CryptoError::from)
}

/// Validates that the configured trusted-channel identity is internally consistent.
#[uniffi::export]
pub fn validate_configured_trusted_channel_identity(
    sub_ca_cvc: Vec<u8>,
    end_entity_cvc: Vec<u8>,
    private_key_der: Vec<u8>,
) -> Result<(), CryptoError> {
    if sub_ca_cvc.is_empty() {
        return Err(CryptoError::InvalidArgument { reason: "sub_ca_cvc must not be empty".to_string() });
    }
    if end_entity_cvc.is_empty() {
        return Err(CryptoError::InvalidArgument { reason: "end_entity_cvc must not be empty".to_string() });
    }
    if private_key_der.is_empty() {
        return Err(CryptoError::InvalidArgument { reason: "private_key_der must not be empty".to_string() });
    }

    let sub_ca_certificate =
        ParsedCvCertificate::parse(&sub_ca_cvc).map_err(|err| CryptoError::Asn1Decode { reason: err.to_string() })?;
    let end_entity_certificate = ParsedCvCertificate::parse(&end_entity_cvc)
        .map_err(|err| CryptoError::Asn1Decode { reason: err.to_string() })?;
    let private_key = EcPrivateKey::decode_from_asn1(&private_key_der).map_err(CryptoError::from)?;

    if sub_ca_certificate.is_end_entity() {
        return Err(CryptoError::InvalidArgument {
            reason: "configured issuer CVC is not a CA certificate".to_string(),
        });
    }
    if !end_entity_certificate.is_end_entity() {
        return Err(CryptoError::InvalidArgument {
            reason: "configured service CVC is not an end-entity certificate".to_string(),
        });
    }
    if sub_ca_certificate.certificate_holder_reference() != end_entity_certificate.certification_authority_reference() {
        return Err(CryptoError::InvalidArgument {
            reason: "configured CVC certificates do not form a chain".to_string(),
        });
    }
    if !private_key_matches_cvc_public_key(&end_entity_certificate, &private_key)? {
        return Err(CryptoError::InvalidArgument {
            reason: "configured service private key does not match configured service CVC".to_string(),
        });
    }

    Ok(())
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

fn private_key_matches_cvc_public_key(
    end_entity_certificate: &ParsedCvCertificate,
    private_key: &EcPrivateKey,
) -> Result<bool, CryptoError> {
    let public_point = end_entity_certificate
        .body
        .public_key
        .public_point()
        .map_err(|err| CryptoError::Asn1Decode { reason: err.to_string() })?;
    let expected_public_key =
        EcPublicKey::from_uncompressed(private_key.curve().clone(), public_point).map_err(CryptoError::from)?;
    let private_scalar = BigInt::from_bytes_be(Sign::Plus, private_key.as_bytes());
    let derived_public_key = private_key
        .curve()
        .g()
        .mul(&private_scalar)
        .map_err(CryptoError::from)?
        .to_ec_public_key()
        .map_err(CryptoError::from)?;
    Ok(derived_public_key.as_bytes() == expected_public_key.as_bytes())
}
#[cfg(test)]
mod tests {
    use super::*;
    use openhealth_asn1::encoder::Asn1Encoder;
    use openhealth_asn1::error::Asn1EncoderError;
    use openhealth_asn1::oid::ObjectIdentifier;
    use openhealth_asn1::tag::TagNumberExt;
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

    fn build_test_cvc(car: &[u8], chr: &[u8], public_point: &[u8], end_entity: bool) -> Vec<u8> {
        Asn1Encoder::write_nonzeroizing::<Asn1EncoderError>(|writer| {
            writer.write_tagged_object(33u8.application_tag().constructed(), |cert| -> Result<(), Asn1EncoderError> {
                cert.write_tagged_object(
                    78u8.application_tag().constructed(),
                    |body| -> Result<(), Asn1EncoderError> {
                        body.write_tagged_object(41u8.application_tag(), |field| -> Result<(), Asn1EncoderError> {
                            field.write_bytes(&[0x00]);
                            Ok(())
                        })?;
                        body.write_tagged_object(2u8.application_tag(), |field| -> Result<(), Asn1EncoderError> {
                            field.write_bytes(car);
                            Ok(())
                        })?;
                        body.write_tagged_object(
                            73u8.application_tag().constructed(),
                            |field| -> Result<(), Asn1EncoderError> {
                                field.write_object_identifier(&ObjectIdentifier::parse("1.3.36.3.5.3.1").unwrap())?;
                                field.write_tagged_object(
                                    0x06u8.context_tag(),
                                    |point| -> Result<(), Asn1EncoderError> {
                                        point.write_bytes(public_point);
                                        Ok(())
                                    },
                                )?;
                                Ok(())
                            },
                        )?;
                        body.write_tagged_object(32u8.application_tag(), |field| -> Result<(), Asn1EncoderError> {
                            field.write_bytes(chr);
                            Ok(())
                        })?;
                        body.write_tagged_object(
                            76u8.application_tag().constructed(),
                            |chat| -> Result<(), Asn1EncoderError> {
                                chat.write_object_identifier(&ObjectIdentifier::parse("1.2.276.0.76.4.152").unwrap())?;
                                chat.write_tagged_object(
                                    19u8.application_tag(),
                                    |data| -> Result<(), Asn1EncoderError> {
                                        data.write_bytes(if end_entity { &[0x00] } else { &[0x80] });
                                        Ok(())
                                    },
                                )?;
                                Ok(())
                            },
                        )?;
                        body.write_tagged_object(37u8.application_tag(), |field| -> Result<(), Asn1EncoderError> {
                            field.write_bytes(&[2, 6, 0, 4, 2, 1]);
                            Ok(())
                        })?;
                        body.write_tagged_object(36u8.application_tag(), |field| -> Result<(), Asn1EncoderError> {
                            field.write_bytes(&[2, 9, 0, 4, 2, 1]);
                            Ok(())
                        })?;
                        Ok(())
                    },
                )?;
                cert.write_tagged_object(55u8.application_tag(), |signature| -> Result<(), Asn1EncoderError> {
                    signature.write_bytes(&[0x00]);
                    Ok(())
                })?;
                Ok(())
            })
        })
        .unwrap()
        .to_vec()
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

    #[test]
    fn validate_configured_trusted_channel_identity_accepts_matching_material() {
        let (sub_ca_public_key, _) = EcKeyPairSpec { curve: EcCurve::BrainpoolP256r1 }.generate_keypair().unwrap();
        let (service_public_key, service_private_key) =
            EcKeyPairSpec { curve: EcCurve::BrainpoolP256r1 }.generate_keypair().unwrap();
        let sub_ca_cvc = build_test_cvc(b"ROOT0001", b"SVCISS01", sub_ca_public_key.as_bytes(), false);
        let end_entity_cvc = build_test_cvc(b"SVCISS01", b"SVCEND01", service_public_key.as_bytes(), true);

        let result = validate_configured_trusted_channel_identity(
            sub_ca_cvc,
            end_entity_cvc,
            service_private_key.encode_to_asn1().unwrap().to_vec(),
        );

        assert!(result.is_ok());
    }

    #[test]
    fn validate_configured_trusted_channel_identity_rejects_mismatched_private_key() {
        let (sub_ca_public_key, _) = EcKeyPairSpec { curve: EcCurve::BrainpoolP256r1 }.generate_keypair().unwrap();
        let (service_public_key, _) = EcKeyPairSpec { curve: EcCurve::BrainpoolP256r1 }.generate_keypair().unwrap();
        let (_, wrong_private_key) = EcKeyPairSpec { curve: EcCurve::BrainpoolP256r1 }.generate_keypair().unwrap();
        let sub_ca_cvc = build_test_cvc(b"ROOT0001", b"SVCISS01", sub_ca_public_key.as_bytes(), false);
        let end_entity_cvc = build_test_cvc(b"SVCISS01", b"SVCEND01", service_public_key.as_bytes(), true);

        let result = validate_configured_trusted_channel_identity(
            sub_ca_cvc,
            end_entity_cvc,
            wrong_private_key.encode_to_asn1().unwrap().to_vec(),
        );

        assert!(matches!(
            result,
            Err(CryptoError::InvalidArgument { reason })
                if reason == "configured service private key does not match configured service CVC"
        ));
    }
}
