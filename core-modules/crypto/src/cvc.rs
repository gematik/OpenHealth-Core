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

use std::time::SystemTime;

use chrono::{DateTime, Datelike, Utc};
use openhealth_asn1::cv_certificate::{CVCertPublicKey, CVCertificate, CertificateDate};
use openhealth_asn1::decoder::Asn1Decoder;
use openhealth_asn1::encoder::Asn1Encoder;
use openhealth_asn1::extraction::extract_context_values;
use openhealth_asn1::tag::{TagNumberExt, UniversalTag};

use crate::error::{CryptoError, CryptoResult};
use crate::ossl::ec::EcPublicKey;
use crate::ossl::signature;

const CVC_PROFILE_G2: u8 = 0x70;
const OID_CVC_ECDSA_PUBLIC_KEY: &str = "1.3.36.3.5.3.1";
const OID_ECDSA_SHA256: &str = "1.2.840.10045.4.3.2";
const OID_ECDSA_SHA384: &str = "1.2.840.10045.4.3.3";
const OID_ECDSA_SHA512: &str = "1.2.840.10045.4.3.4";

#[derive(Debug, Clone)]
pub struct CvcTrustAnchor {
    reference: Vec<u8>,
    public_key: CvcPublicKey,
}

impl CvcTrustAnchor {
    pub fn from_certificate(certificate: &CVCertificate) -> CryptoResult<Self> {
        let public_key = CvcPublicKey::from_cert_public_key(&certificate.body.public_key)?;
        Ok(Self { reference: certificate.body.certificate_holder_reference.clone(), public_key })
    }

    pub fn from_public_key_tlv(reference: Vec<u8>, public_key_tlv: &[u8]) -> CryptoResult<Self> {
        if reference.is_empty() {
            return Err(invalid_chain("trust anchor reference must not be empty"));
        }
        let public_key = parse_public_key_tlv(public_key_tlv)?;
        Ok(Self { reference, public_key })
    }

    pub fn reference(&self) -> &[u8] {
        &self.reference
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CvcChainValidationResult {
    validated_certificates: usize,
    end_entity_chr: Vec<u8>,
}

impl CvcChainValidationResult {
    pub fn validated_certificates(&self) -> usize {
        self.validated_certificates
    }

    pub fn end_entity_chr(&self) -> &[u8] {
        &self.end_entity_chr
    }
}

#[derive(Debug, Clone)]
struct CvcPublicKey {
    point: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct CvcDate {
    year: i32,
    month: u32,
    day: u32,
}

#[derive(Debug, Clone, Copy)]
struct SignatureProfile {
    curve_name: &'static str,
    digest_name: &'static str,
    coordinate_len: usize,
}

pub fn validate_cvc_chain(
    chain: &[CVCertificate],
    trust_anchors: &[CvcTrustAnchor],
    validation_time: SystemTime,
) -> CryptoResult<CvcChainValidationResult> {
    if chain.is_empty() {
        return Err(invalid_chain("chain must not be empty"));
    }
    if trust_anchors.is_empty() {
        return Err(invalid_chain("at least one trust anchor is required"));
    }

    let validation_date = system_time_to_utc_date(validation_time);
    let first = &chain[0];
    validate_profile_and_date(first, validation_date)?;
    let trust_anchor = trust_anchors
        .iter()
        .find(|anchor| anchor.reference == first.body.certification_authority_reference)
        .ok_or_else(|| invalid_chain("no trust anchor matching first certificate CAR"))?;
    verify_certificate_signature(first, &trust_anchor.public_key, "trust anchor")?;

    let mut issuer_public_key = CvcPublicKey::from_cert_public_key(&first.body.public_key)?;
    let mut issuer = first;
    for child in chain.iter().skip(1) {
        validate_profile_and_date(child, validation_date)?;
        if child.body.certification_authority_reference != issuer.body.certificate_holder_reference {
            return Err(invalid_chain("certificate CAR does not match issuer CHR"));
        }
        validate_chat_is_subset(issuer, child)?;
        verify_certificate_signature(child, &issuer_public_key, "issuer certificate")?;
        issuer_public_key = CvcPublicKey::from_cert_public_key(&child.body.public_key)?;
        issuer = child;
    }

    let end_entity_chr =
        chain.last().ok_or_else(|| invalid_chain("chain must not be empty"))?.body.certificate_holder_reference.clone();
    Ok(CvcChainValidationResult { validated_certificates: chain.len(), end_entity_chr })
}

pub fn verify_cvc_ecdsa_value_signature(
    certificate: &CVCertificate,
    value: &[u8],
    signature: &[u8],
) -> CryptoResult<bool> {
    let public_key = CvcPublicKey::from_cert_public_key(&certificate.body.public_key)?;
    verify_ecdsa_value_signature(&public_key.point, value, signature)
}

pub fn verify_ecdsa_value_signature(public_key: &[u8], value: &[u8], signature: &[u8]) -> CryptoResult<bool> {
    if value.is_empty() {
        return Err(invalid_chain("ECDSA value must not be empty"));
    }

    let profile = SignatureProfile::from_point_len(public_key.len())?;
    let signature = der_encode_plain_ecdsa_signature(signature, profile.coordinate_len)?;
    let public_key = EcPublicKey::from_uncompressed(profile.curve_name, public_key)?;
    signature::verify_ecdsa_digest(&public_key, value, &signature).map_err(CryptoError::from)
}

fn validate_profile_and_date(certificate: &CVCertificate, validation_date: CvcDate) -> CryptoResult<()> {
    if certificate.body.profile_identifier != CVC_PROFILE_G2 {
        return Err(invalid_chain(format!(
            "unsupported CVC profile identifier 0x{:02X}",
            certificate.body.profile_identifier
        )));
    }
    let not_before = CvcDate::from_certificate_date(certificate.body.certificate_effective_date);
    let not_after = CvcDate::from_certificate_date(certificate.body.certificate_expiration_date);
    if validation_date < not_before {
        return Err(invalid_chain("certificate is not yet effective"));
    }
    if validation_date > not_after {
        return Err(invalid_chain("certificate is expired"));
    }
    Ok(())
}

fn validate_chat_is_subset(issuer: &CVCertificate, child: &CVCertificate) -> CryptoResult<()> {
    let issuer_chat = &issuer.body.certificate_holder_authorization_template;
    let child_chat = &child.body.certificate_holder_authorization_template;
    if issuer_chat.terminal_type != child_chat.terminal_type {
        return Err(invalid_chain("child CHAT terminal type differs from issuer"));
    }
    if issuer_chat.relative_authorization.len() != child_chat.relative_authorization.len() {
        return Err(invalid_chain("child CHAT authorization length differs from issuer"));
    }
    if child_chat
        .relative_authorization
        .iter()
        .zip(issuer_chat.relative_authorization.iter())
        .any(|(child, issuer)| child & !issuer != 0)
    {
        return Err(invalid_chain("child CHAT authorization is not a subset of issuer authorization"));
    }
    Ok(())
}

fn verify_certificate_signature(
    certificate: &CVCertificate,
    issuer_public_key: &CvcPublicKey,
    issuer_label: &str,
) -> CryptoResult<()> {
    let profile =
        SignatureProfile::from_public_key_and_algorithm(issuer_public_key, &certificate.body.public_key.key_oid)?;
    let signature = der_encode_plain_ecdsa_signature(&certificate.signature, profile.coordinate_len)?;
    let public_key = EcPublicKey::from_uncompressed(profile.curve_name, &issuer_public_key.point)?;
    let valid =
        signature::verify_ecdsa_message(&public_key, profile.digest_name, certificate.encoded_body_tlv(), &signature)?;
    if valid {
        Ok(())
    } else {
        Err(CryptoError::InvalidCvcSignature { context: format!("signature check failed with {issuer_label}") })
    }
}

fn parse_public_key_tlv(data: &[u8]) -> CryptoResult<CvcPublicKey> {
    let point = Asn1Decoder::new(data).read(|scope| {
        scope.advance_with_tag(73u8.application_tag().constructed(), |scope| {
            let _oid = scope.read_object_identifier()?;
            let key_data = scope.read_bytes(scope.remaining_length())?;
            let values = extract_context_values(&key_data, 6)?;
            values.last().cloned().ok_or_else(|| {
                openhealth_asn1::error::Asn1DecoderError::custom("CVC public key does not contain context tag 6")
            })
        })
    })?;
    SignatureProfile::from_point_len(point.len())?;
    Ok(CvcPublicKey { point })
}

impl CvcPublicKey {
    fn from_cert_public_key(public_key: &CVCertPublicKey) -> CryptoResult<Self> {
        let values = extract_context_values(&public_key.key_data, 6)?;
        let point =
            values.last().cloned().ok_or_else(|| invalid_chain("CVC public key does not contain context tag 6"))?;
        SignatureProfile::from_point_len(point.len())?;
        Ok(Self { point })
    }
}

impl SignatureProfile {
    fn from_point_len(point_len: usize) -> CryptoResult<Self> {
        match point_len {
            65 => Ok(Self { curve_name: "brainpoolP256r1", digest_name: "SHA256", coordinate_len: 32 }),
            97 => Ok(Self { curve_name: "brainpoolP384r1", digest_name: "SHA384", coordinate_len: 48 }),
            129 => Ok(Self { curve_name: "brainpoolP512r1", digest_name: "SHA512", coordinate_len: 64 }),
            _ => Err(invalid_chain(format!("unsupported CVC public key point length {point_len}"))),
        }
    }

    fn from_public_key_and_algorithm(
        public_key: &CvcPublicKey,
        algorithm_oid: &openhealth_asn1::oid::ObjectIdentifier,
    ) -> CryptoResult<Self> {
        let profile = Self::from_point_len(public_key.point.len())?;
        let expected_oid = match profile.coordinate_len {
            32 => OID_ECDSA_SHA256,
            48 => OID_ECDSA_SHA384,
            64 => OID_ECDSA_SHA512,
            _ => unreachable!(),
        };
        let algorithm_oid = algorithm_oid.to_string();
        if algorithm_oid != expected_oid && algorithm_oid != OID_CVC_ECDSA_PUBLIC_KEY {
            return Err(invalid_chain(format!(
                "unsupported or mismatched CVC signature algorithm OID {algorithm_oid}"
            )));
        }
        Ok(profile)
    }
}

impl CvcDate {
    fn from_certificate_date(date: CertificateDate) -> Self {
        Self { year: 2000 + i32::from(date.year), month: u32::from(date.month), day: u32::from(date.day) }
    }
}

fn system_time_to_utc_date(time: SystemTime) -> CvcDate {
    let datetime: DateTime<Utc> = time.into();
    CvcDate { year: datetime.year(), month: datetime.month(), day: datetime.day() }
}

fn der_encode_plain_ecdsa_signature(signature: &[u8], coordinate_len: usize) -> CryptoResult<Vec<u8>> {
    let expected_len = coordinate_len * 2;
    if signature.len() != expected_len {
        return Err(invalid_chain(format!(
            "invalid CVC ECDSA signature length: expected {expected_len}, got {}",
            signature.len()
        )));
    }
    let encoded = Asn1Encoder::write_nonzeroizing::<CryptoError>(|scope| {
        scope.write_tagged_object(UniversalTag::Sequence.constructed(), |sequence| -> CryptoResult<()> {
            sequence.write_asn1_unsigned_integer_bytes(&signature[..coordinate_len])?;
            sequence.write_asn1_unsigned_integer_bytes(&signature[coordinate_len..])?;
            Ok(())
        })
    })?;
    Ok(encoded.as_ref().to_vec())
}

fn invalid_chain(context: impl Into<String>) -> CryptoError {
    CryptoError::InvalidCvcChain { context: context.into() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::digest::DigestSpec;
    use chrono::TimeZone;
    use std::fs;
    use std::path::PathBuf;

    fn fixture_path(parts: &[&str]) -> PathBuf {
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.pop();
        path.pop();
        path.push("test-vectors");
        path.push("cvc-chain");
        path.push("pki_cvc_g2_input");
        for part in parts {
            path.push(part);
        }
        path
    }

    fn load_cvc(name: &str) -> CVCertificate {
        let path = fixture_path(&["Atos_CVC-Root-CA", name]);
        let bytes = fs::read(path).expect("fixture should be readable");
        CVCertificate::parse(&bytes).expect("fixture should parse")
    }

    fn load_anchor(reference: &[u8], name: &str) -> CvcTrustAnchor {
        let path = fixture_path(&["trust-anchor", name]);
        let bytes = fs::read(path).expect("fixture should be readable");
        CvcTrustAnchor::from_public_key_tlv(reference.to_vec(), &bytes).expect("anchor should parse")
    }

    fn validation_time(year: i32, month: u32, day: u32) -> SystemTime {
        Utc.with_ymd_and_hms(year, month, day, 12, 0, 0).single().unwrap().into()
    }

    fn sha256(data: &[u8]) -> Vec<u8> {
        let mut digest = DigestSpec::Sha256.create().unwrap();
        digest.update(data).unwrap();
        digest.finalize().unwrap()
    }

    fn cvc_with_public_key_oid() -> CVCertificate {
        let hex_data = "\
            7f2181da7f4e81935f290170420844454758581102237f494b06062b24030503\
            018641045e7ae614740e7012e350de71c10021ec668f21d6859591b4f709c4c7\
            3cce91c5a7fb0be1327e59ff1d0cb402b9c2bb0dc0432fa566bd4ff5f532258c\
            7364aecd5f200c0009802768831100001565497f4c1306082a8214004c048118\
            5307000000000000005f25060204000400025f24060209000400015f37409d24\
            4d497832172304f298bd49f91f45bf346cb306adeb44b0742017a074902146cc\
            cbdbb35426c2eb602d38253d92ebe1ac6905f388407398a474c4ea612d84";
        let data = hex::decode(hex_data.split_whitespace().collect::<String>()).unwrap();
        CVCertificate::parse(&data).expect("fixture should parse")
    }

    #[test]
    fn validates_self_signed_root_against_public_key_anchor() {
        let cert = load_cvc("DEGXX820214.cvc");
        let anchor = load_anchor(&hex::decode("4445475858820214").unwrap(), "4445475858820214_ELC-PublicKey.der");

        let result = validate_cvc_chain(&[cert], &[anchor], validation_time(2020, 1, 1)).unwrap();

        assert_eq!(result.validated_certificates(), 1);
        assert_eq!(hex::encode(result.end_entity_chr()), "4445475858820214");
    }

    #[test]
    fn validates_cross_signed_chain_against_public_key_anchor() {
        let issuer = load_cvc("DEGXX830214_cross.cvc");
        let child = load_cvc("DEGXX840216_830214_cross.cvc");
        let anchor = load_anchor(&hex::decode("4445475858820214").unwrap(), "4445475858820214_ELC-PublicKey.der");

        let result = validate_cvc_chain(&[issuer, child], &[anchor], validation_time(2017, 1, 1)).unwrap();

        assert_eq!(result.validated_certificates(), 2);
        assert_eq!(hex::encode(result.end_entity_chr()), "4445475858840216");
    }

    #[test]
    fn accepts_cvc_public_key_oid_for_signature_profile() {
        let cert = cvc_with_public_key_oid();
        let public_key = CvcPublicKey::from_cert_public_key(&cert.body.public_key).unwrap();

        let profile =
            SignatureProfile::from_public_key_and_algorithm(&public_key, &cert.body.public_key.key_oid).unwrap();

        assert_eq!(profile.coordinate_len, 32);
        assert_eq!(profile.curve_name, "brainpoolP256r1");
        assert_eq!(profile.digest_name, "SHA256");
    }

    #[test]
    fn verifies_raw_ecdsa_value_signature() {
        let cert = load_cvc("DEGXX820214.cvc");
        let public_key = CvcPublicKey::from_cert_public_key(&cert.body.public_key).unwrap();
        let digest = sha256(cert.encoded_body_tlv());

        let valid = verify_ecdsa_value_signature(&public_key.point, &digest, &cert.signature).unwrap();

        assert!(valid);
    }

    #[test]
    fn rejects_tampered_raw_ecdsa_value_signature() {
        let cert = load_cvc("DEGXX820214.cvc");
        let public_key = CvcPublicKey::from_cert_public_key(&cert.body.public_key).unwrap();
        let mut digest = sha256(cert.encoded_body_tlv());
        digest[0] ^= 0x01;

        let valid = verify_ecdsa_value_signature(&public_key.point, &digest, &cert.signature).unwrap();

        assert!(!valid);
    }

    #[test]
    fn rejects_tampered_signature() {
        let mut cert = load_cvc("DEGXX820214.cvc");
        let anchor = load_anchor(&hex::decode("4445475858820214").unwrap(), "4445475858820214_ELC-PublicKey.der");
        cert.signature[0] ^= 0x01;

        let err = validate_cvc_chain(&[cert], &[anchor], validation_time(2020, 1, 1)).unwrap_err();

        assert!(matches!(err, CryptoError::InvalidCvcSignature { .. }));
    }

    #[test]
    fn rejects_expired_certificate() {
        let cert = load_cvc("DEGXX820214.cvc");
        let anchor = load_anchor(&hex::decode("4445475858820214").unwrap(), "4445475858820214_ELC-PublicKey.der");

        let err = validate_cvc_chain(&[cert], &[anchor], validation_time(2025, 1, 1)).unwrap_err();

        assert!(matches!(err, CryptoError::InvalidCvcChain { .. }));
    }

    #[test]
    fn rejects_wrong_trust_anchor_reference() {
        let cert = load_cvc("DEGXX820214.cvc");
        let anchor = load_anchor(&hex::decode("4445475858830214").unwrap(), "4445475858820214_ELC-PublicKey.der");

        let err = validate_cvc_chain(&[cert], &[anchor], validation_time(2020, 1, 1)).unwrap_err();

        assert!(matches!(err, CryptoError::InvalidCvcChain { .. }));
    }
}
