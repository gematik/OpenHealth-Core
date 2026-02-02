// SPDX-FileCopyrightText: Copyright 2025 - 2026 gematik GmbH
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

//! Card verifiable certificate (CVC) parsing.
//!
//! This module provides a lightweight parser for so-called "CV Certificates" as used in EAC-based
//! ecosystems. The parser is intentionally focused on structural decoding:
//!
//! - It extracts the certificate body and signature as raw bytes/fields.
//! - It does **not** verify the signature, validity period, or any certificate chain.
//! - It enforces basic length and format constraints to avoid excessive allocations and to reject
//!   obviously malformed inputs early.
//!
//! Encoding notes:
//! - The outer container is expected to be an application-specific, constructed tag `33`.
//! - Dates are encoded as 6 digits (`YYMMDD`), where each digit is stored in a single octet with
//!   value `0..=9` (not ASCII).

use crate::decoder::{Asn1Decoder, Asn1Length, ParserScope};
use crate::error::{Asn1DecoderError, Asn1DecoderResult};
use crate::oid::ObjectIdentifier;
use crate::tag::{Asn1Id, TagNumberExt};

const TAG_CV_CERTIFICATE: u32 = 33;
const TAG_CERTIFICATE_BODY: u32 = 78;
const TAG_PROFILE_IDENTIFIER: u32 = 41;
const TAG_CERTIFICATION_AUTHORITY_REFERENCE: u32 = 2;
const TAG_PUBLIC_KEY: u32 = 73;
const TAG_CERTIFICATE_HOLDER_REFERENCE: u32 = 32;
const TAG_CHAT: u32 = 76;
const TAG_CERTIFICATE_EFFECTIVE_DATE: u32 = 37;
const TAG_CERTIFICATE_EXPIRATION_DATE: u32 = 36;
const TAG_CERTIFICATE_EXTENSIONS: u32 = 5;
const TAG_DISCRETIONARY_DATA: u32 = 19;
const TAG_SIGNATURE: u32 = 55;

const MAX_CERT_FIELD_LEN: usize = 65_535;

#[derive(Debug, Clone, PartialEq, Eq)]
/// A parsed CV certificate consisting of the certificate [`CertificateBody`] and the raw signature.
///
/// The signature is returned as the content octets of the signature field (no verification is
/// performed).
pub struct CVCertificate {
    pub body: CertificateBody,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// The body of a CV certificate.
///
/// Several fields are kept as raw bytes because their semantics are domain-specific (e.g. CAR/CHR
/// formatting, public key data layout). Consumers can interpret these bytes according to their
/// profile/specification.
pub struct CertificateBody {
    pub profile_identifier: u8,
    pub certification_authority_reference: Vec<u8>,
    pub public_key: CVCertPublicKey,
    pub certificate_holder_reference: Vec<u8>,
    pub certificate_holder_authorization_template: Chat,
    pub certificate_effective_date: CertificateDate,
    pub certificate_expiration_date: CertificateDate,
    pub certificate_extensions: Option<CertificateExtensions>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Public key information carried in the certificate body.
///
/// - `key_oid` identifies the public key algorithm / key type.
/// - `key_data` contains the raw, context-specific key data objects that follow the OID.
pub struct CVCertPublicKey {
    pub key_oid: ObjectIdentifier,
    /// Raw contents after the key OID (context-specific key data objects).
    pub key_data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Certificate Holder Authorization Template (CHAT).
///
/// `relative_authorization` is kept as raw bytes (content octets) because its layout depends on the
/// terminal type / profile.
pub struct Chat {
    pub terminal_type: ObjectIdentifier,
    pub relative_authorization: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// A CVC date encoded as digits `YYMMDD`.
///
/// Each digit is stored as an octet `0..=9` (e.g. `250101` is `[2, 5, 0, 1, 0, 1]`).
pub struct CertificateDate {
    pub year: u8,
    pub month: u8,
    pub day: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Optional extensions carried in the certificate body.
///
/// Extensions are represented as discretionary data templates.
pub struct CertificateExtensions {
    pub templates: Vec<DiscretionaryDataTemplate>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// One discretionary data template within [`CertificateExtensions`].
pub struct DiscretionaryDataTemplate {
    pub extension_id: ObjectIdentifier,
    pub extension_data: Vec<ExtensionField>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// A raw extension field inside a discretionary data template.
///
/// `tag` is read verbatim from the input. `value` is the field's content octets. Indefinite-length
/// encodings are rejected.
pub struct ExtensionField {
    pub tag: Asn1Id,
    pub value: Vec<u8>,
}

impl CVCertificate {
    /// Parse a CV certificate from BER/DER-like TLV encoded bytes.
    ///
    /// This validates:
    /// - expected application tags/structure,
    /// - basic length constraints for selected fields (e.g. CAR/CHR),
    /// - date digit ranges and basic calendar constraints (month `1..=12`, day `1..=31`),
    /// - and rejects indefinite-length values in extension fields.
    pub fn parse(data: &[u8]) -> Asn1DecoderResult<Self> {
        let decoder = Asn1Decoder::new(data);
        let certificate = decoder.read(|scope| parse_cv_certificate_scope(scope))?;
        Ok(certificate)
    }
}

/// Parse a CV certificate from bytes.
///
/// This is a convenience wrapper around [`CVCertificate::parse`].
pub fn parse_cv_certificate(data: &[u8]) -> Asn1DecoderResult<CVCertificate> {
    CVCertificate::parse(data)
}

fn parse_cv_certificate_scope(scope: &mut ParserScope) -> Result<CVCertificate, Asn1DecoderError> {
    scope.advance_with_tag(TAG_CV_CERTIFICATE.application_tag().constructed(), |scope| {
        let body = parse_certificate_body(scope)?;
        let signature = read_application_bytes(scope, TAG_SIGNATURE, 0, MAX_CERT_FIELD_LEN)?;
        Ok(CVCertificate { body, signature })
    })
}

fn parse_certificate_body(scope: &mut ParserScope) -> Result<CertificateBody, Asn1DecoderError> {
    scope.advance_with_tag(TAG_CERTIFICATE_BODY.application_tag().constructed(), |scope| {
        let profile_identifier = read_profile_identifier(scope)?;
        let certification_authority_reference =
            read_application_bytes(scope, TAG_CERTIFICATION_AUTHORITY_REFERENCE, 1, 16)?;
        let public_key = parse_public_key(scope)?;
        let certificate_holder_reference = read_application_bytes(scope, TAG_CERTIFICATE_HOLDER_REFERENCE, 1, 16)?;
        let certificate_holder_authorization_template = parse_chat(scope)?;
        let certificate_effective_date = parse_date(scope, TAG_CERTIFICATE_EFFECTIVE_DATE)?;
        let certificate_expiration_date = parse_date(scope, TAG_CERTIFICATE_EXPIRATION_DATE)?;
        let certificate_extensions =
            if scope.remaining_length() > 0 { Some(parse_certificate_extensions(scope)?) } else { None };

        Ok(CertificateBody {
            profile_identifier,
            certification_authority_reference,
            public_key,
            certificate_holder_reference,
            certificate_holder_authorization_template,
            certificate_effective_date,
            certificate_expiration_date,
            certificate_extensions,
        })
    })
}

fn read_profile_identifier(scope: &mut ParserScope) -> Result<u8, Asn1DecoderError> {
    let bytes = read_application_bytes(scope, TAG_PROFILE_IDENTIFIER, 1, 4)?;
    if (bytes[0] & 0x80) != 0 {
        return Err(Asn1DecoderError::custom("CertificateProfileIdentifier must be a non-negative INTEGER"));
    }
    let value = bytes.iter().fold(0u32, |acc, b| (acc << 8) | (*b as u32));
    if value > u8::MAX as u32 {
        return Err(Asn1DecoderError::custom("CertificateProfileIdentifier must be within 0..=255"));
    }
    Ok(value as u8)
}

fn parse_public_key(scope: &mut ParserScope) -> Result<CVCertPublicKey, Asn1DecoderError> {
    scope.advance_with_tag(TAG_PUBLIC_KEY.application_tag().constructed(), |scope| {
        let key_oid = scope.read_object_identifier()?;
        let key_data = scope.read_bytes(scope.remaining_length())?;
        if key_data.is_empty() {
            return Err(Asn1DecoderError::custom("CVCertPublicKey data must not be empty"));
        }
        Ok(CVCertPublicKey { key_oid, key_data })
    })
}

fn parse_chat(scope: &mut ParserScope) -> Result<Chat, Asn1DecoderError> {
    scope.advance_with_tag(TAG_CHAT.application_tag().constructed(), |scope| {
        let terminal_type = scope.read_object_identifier()?;
        let relative_authorization = read_application_bytes(scope, TAG_DISCRETIONARY_DATA, 0, MAX_CERT_FIELD_LEN)?;
        Ok(Chat { terminal_type, relative_authorization })
    })
}

fn parse_date(scope: &mut ParserScope, tag_number: u32) -> Result<CertificateDate, Asn1DecoderError> {
    let bytes = read_application_bytes(scope, tag_number, 6, 6)?;
    parse_date_bytes(&bytes)
}

fn parse_certificate_extensions(scope: &mut ParserScope) -> Result<CertificateExtensions, Asn1DecoderError> {
    scope.advance_with_tag(TAG_CERTIFICATE_EXTENSIONS.application_tag().constructed(), |scope| {
        let mut templates = Vec::new();
        while scope.remaining_length() > 0 {
            templates.push(parse_discretionary_data_template(scope)?);
        }
        Ok(CertificateExtensions { templates })
    })
}

fn parse_discretionary_data_template(scope: &mut ParserScope) -> Result<DiscretionaryDataTemplate, Asn1DecoderError> {
    scope.advance_with_tag(TAG_DISCRETIONARY_DATA.application_tag().constructed(), |scope| {
        let extension_id = scope.read_object_identifier()?;
        let mut extension_data = Vec::new();
        while scope.remaining_length() > 0 {
            extension_data.push(parse_extension_field(scope)?);
        }
        Ok(DiscretionaryDataTemplate { extension_id, extension_data })
    })
}

fn parse_extension_field(scope: &mut ParserScope) -> Result<ExtensionField, Asn1DecoderError> {
    let tag = scope.read_tag()?;
    let length = scope.read_length()?;
    let value = match length {
        Asn1Length::Definite(len) => scope.read_bytes(len)?,
        Asn1Length::Indefinite => {
            return Err(Asn1DecoderError::custom("Indefinite length is not supported for extension fields"))
        }
    };
    Ok(ExtensionField { tag, value })
}

fn read_application_bytes(
    scope: &mut ParserScope,
    tag_number: u32,
    min_len: usize,
    max_len: usize,
) -> Result<Vec<u8>, Asn1DecoderError> {
    scope.advance_with_tag(tag_number.application_tag().primitive(), |scope| {
        let len = scope.remaining_length();
        if len < min_len || len > max_len {
            return Err(Asn1DecoderError::custom(format!("Invalid length {len} for application tag {tag_number}")));
        }
        scope.read_bytes(len)
    })
}

fn parse_date_bytes(bytes: &[u8]) -> Result<CertificateDate, Asn1DecoderError> {
    for (idx, byte) in bytes.iter().enumerate() {
        if *byte > 9 {
            return Err(Asn1DecoderError::custom(format!("Certificate date digit {idx} must be 0..9")));
        }
    }
    let year = bytes[0] * 10 + bytes[1];
    let month = bytes[2] * 10 + bytes[3];
    let day = bytes[4] * 10 + bytes[5];
    if !(1..=12).contains(&month) {
        return Err(Asn1DecoderError::custom("Certificate month must be 1..=12"));
    }
    if !(1..=31).contains(&day) {
        return Err(Asn1DecoderError::custom("Certificate day must be 1..=31"));
    }
    Ok(CertificateDate { year, month, day })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoder::Asn1Encoder;
    use crate::tag::TagNumberExt;

    type EncResult = Result<(), crate::error::Asn1EncoderError>;

    fn build_test_certificate(with_extensions: bool) -> Vec<u8> {
        Asn1Encoder::write::<crate::error::Asn1EncoderError>(|w| {
            w.write_tagged_object(TAG_CV_CERTIFICATE.application_tag().constructed(), |cert| -> EncResult {
                cert.write_tagged_object(TAG_CERTIFICATE_BODY.application_tag().constructed(), |body| -> EncResult {
                    body.write_tagged_object(TAG_PROFILE_IDENTIFIER.application_tag(), |field| -> EncResult {
                        field.write_byte(0x00);
                        Ok(())
                    })?;
                    body.write_tagged_object(
                        TAG_CERTIFICATION_AUTHORITY_REFERENCE.application_tag(),
                        |field| -> EncResult {
                            field.write_bytes(b"CAR");
                            Ok(())
                        },
                    )?;
                    body.write_tagged_object(TAG_PUBLIC_KEY.application_tag().constructed(), |field| -> EncResult {
                        let oid = ObjectIdentifier::parse("1.2.3.4").expect("valid OID");
                        field.write_object_identifier(&oid)?;
                        field.write_bytes(&[0xA0, 0x01, 0x02]);
                        Ok(())
                    })?;
                    body.write_tagged_object(
                        TAG_CERTIFICATE_HOLDER_REFERENCE.application_tag(),
                        |field| -> EncResult {
                            field.write_bytes(b"CH");
                            Ok(())
                        },
                    )?;
                    body.write_tagged_object(TAG_CHAT.application_tag().constructed(), |chat| -> EncResult {
                        let oid = ObjectIdentifier::parse("1.2.3").expect("valid OID");
                        chat.write_object_identifier(&oid)?;
                        chat.write_tagged_object(TAG_DISCRETIONARY_DATA.application_tag(), |data| -> EncResult {
                            data.write_bytes(&[0xAA, 0xBB]);
                            Ok(())
                        })?;
                        Ok(())
                    })?;
                    body.write_tagged_object(TAG_CERTIFICATE_EFFECTIVE_DATE.application_tag(), |field| -> EncResult {
                        field.write_bytes(&[2, 5, 0, 1, 0, 1]);
                        Ok(())
                    })?;
                    body.write_tagged_object(
                        TAG_CERTIFICATE_EXPIRATION_DATE.application_tag(),
                        |field| -> EncResult {
                            field.write_bytes(&[2, 6, 1, 2, 3, 1]);
                            Ok(())
                        },
                    )?;

                    if with_extensions {
                        body.write_tagged_object(
                            TAG_CERTIFICATE_EXTENSIONS.application_tag().constructed(),
                            |exts| -> EncResult {
                                exts.write_tagged_object(
                                    TAG_DISCRETIONARY_DATA.application_tag().constructed(),
                                    |tmpl| -> EncResult {
                                        let oid = ObjectIdentifier::parse("1.2.3.4").expect("valid OID");
                                        tmpl.write_object_identifier(&oid)?;
                                        tmpl.write_tagged_object(0u8.context_tag(), |field| -> EncResult {
                                            field.write_bytes(&[0x10]);
                                            Ok(())
                                        })?;
                                        tmpl.write_tagged_object(1u8.context_tag(), |field| -> EncResult {
                                            field.write_bytes(&[0x20, 0x30]);
                                            Ok(())
                                        })?;
                                        Ok(())
                                    },
                                )?;
                                Ok(())
                            },
                        )?;
                    }

                    Ok(())
                })?;
                cert.write_tagged_object(TAG_SIGNATURE.application_tag(), |sig| -> EncResult {
                    sig.write_bytes(&[0xDE, 0xAD]);
                    Ok(())
                })?;
                Ok(())
            })
        })
        .expect("encoding must succeed")
    }

    #[test]
    fn parse_date_rejects_invalid_day() {
        let err = parse_date_bytes(&[2, 5, 0, 1, 3, 2]).unwrap_err();
        assert!(err.to_string().contains("Certificate day"));
    }

    fn build_certificate_with_fields(
        profile_bytes: &[u8],
        car: &[u8],
        chr: &[u8],
        effective: &[u8],
        expiration: &[u8],
    ) -> Vec<u8> {
        build_certificate_with_fields_and_signature(profile_bytes, car, chr, effective, expiration, &[0x00])
    }

    fn build_certificate_with_fields_and_signature(
        profile_bytes: &[u8],
        car: &[u8],
        chr: &[u8],
        effective: &[u8],
        expiration: &[u8],
        signature: &[u8],
    ) -> Vec<u8> {
        Asn1Encoder::write::<crate::error::Asn1EncoderError>(|w| {
            w.write_tagged_object(TAG_CV_CERTIFICATE.application_tag().constructed(), |cert| -> EncResult {
                cert.write_tagged_object(TAG_CERTIFICATE_BODY.application_tag().constructed(), |body| -> EncResult {
                    body.write_tagged_object(TAG_PROFILE_IDENTIFIER.application_tag(), |field| -> EncResult {
                        field.write_bytes(profile_bytes);
                        Ok(())
                    })?;
                    body.write_tagged_object(
                        TAG_CERTIFICATION_AUTHORITY_REFERENCE.application_tag(),
                        |field| -> EncResult {
                            field.write_bytes(car);
                            Ok(())
                        },
                    )?;
                    body.write_tagged_object(TAG_PUBLIC_KEY.application_tag().constructed(), |field| -> EncResult {
                        let oid = ObjectIdentifier::parse("1.2.3.4").expect("valid OID");
                        field.write_object_identifier(&oid)?;
                        field.write_bytes(&[0xA0, 0x01, 0x02]);
                        Ok(())
                    })?;
                    body.write_tagged_object(
                        TAG_CERTIFICATE_HOLDER_REFERENCE.application_tag(),
                        |field| -> EncResult {
                            field.write_bytes(chr);
                            Ok(())
                        },
                    )?;
                    body.write_tagged_object(TAG_CHAT.application_tag().constructed(), |chat| -> EncResult {
                        let oid = ObjectIdentifier::parse("1.2.3").expect("valid OID");
                        chat.write_object_identifier(&oid)?;
                        chat.write_tagged_object(TAG_DISCRETIONARY_DATA.application_tag(), |data| -> EncResult {
                            data.write_bytes(&[0x00]);
                            Ok(())
                        })?;
                        Ok(())
                    })?;
                    body.write_tagged_object(TAG_CERTIFICATE_EFFECTIVE_DATE.application_tag(), |field| -> EncResult {
                        field.write_bytes(effective);
                        Ok(())
                    })?;
                    body.write_tagged_object(
                        TAG_CERTIFICATE_EXPIRATION_DATE.application_tag(),
                        |field| -> EncResult {
                            field.write_bytes(expiration);
                            Ok(())
                        },
                    )?;
                    Ok(())
                })?;
                cert.write_tagged_object(TAG_SIGNATURE.application_tag(), |sig| -> EncResult {
                    sig.write_bytes(signature);
                    Ok(())
                })?;
                Ok(())
            })
        })
        .expect("encoding must succeed")
    }

    fn build_certificate_with_chat_data(chat_data: &[u8]) -> Vec<u8> {
        Asn1Encoder::write::<crate::error::Asn1EncoderError>(|w| {
            w.write_tagged_object(TAG_CV_CERTIFICATE.application_tag().constructed(), |cert| -> EncResult {
                cert.write_tagged_object(TAG_CERTIFICATE_BODY.application_tag().constructed(), |body| -> EncResult {
                    body.write_tagged_object(TAG_PROFILE_IDENTIFIER.application_tag(), |field| -> EncResult {
                        field.write_bytes(&[0x00]);
                        Ok(())
                    })?;
                    body.write_tagged_object(
                        TAG_CERTIFICATION_AUTHORITY_REFERENCE.application_tag(),
                        |field| -> EncResult {
                            field.write_bytes(b"CAR");
                            Ok(())
                        },
                    )?;
                    body.write_tagged_object(TAG_PUBLIC_KEY.application_tag().constructed(), |field| -> EncResult {
                        let oid = ObjectIdentifier::parse("1.2.3.4").expect("valid OID");
                        field.write_object_identifier(&oid)?;
                        field.write_bytes(&[0xA0, 0x01, 0x02]);
                        Ok(())
                    })?;
                    body.write_tagged_object(
                        TAG_CERTIFICATE_HOLDER_REFERENCE.application_tag(),
                        |field| -> EncResult {
                            field.write_bytes(b"CHR");
                            Ok(())
                        },
                    )?;
                    body.write_tagged_object(TAG_CHAT.application_tag().constructed(), |chat| -> EncResult {
                        let oid = ObjectIdentifier::parse("1.2.3").expect("valid OID");
                        chat.write_object_identifier(&oid)?;
                        chat.write_tagged_object(TAG_DISCRETIONARY_DATA.application_tag(), |data| -> EncResult {
                            data.write_bytes(chat_data);
                            Ok(())
                        })?;
                        Ok(())
                    })?;
                    body.write_tagged_object(TAG_CERTIFICATE_EFFECTIVE_DATE.application_tag(), |field| -> EncResult {
                        field.write_bytes(&[2, 5, 0, 1, 0, 1]);
                        Ok(())
                    })?;
                    body.write_tagged_object(
                        TAG_CERTIFICATE_EXPIRATION_DATE.application_tag(),
                        |field| -> EncResult {
                            field.write_bytes(&[2, 5, 0, 1, 0, 2]);
                            Ok(())
                        },
                    )?;
                    Ok(())
                })?;
                cert.write_tagged_object(TAG_SIGNATURE.application_tag(), |sig| -> EncResult {
                    sig.write_bytes(&[0x00]);
                    Ok(())
                })?;
                Ok(())
            })
        })
        .expect("encoding must succeed")
    }

    fn build_certificate_with_public_key(public_key: &[u8]) -> Vec<u8> {
        Asn1Encoder::write::<crate::error::Asn1EncoderError>(|w| {
            w.write_tagged_object(TAG_CV_CERTIFICATE.application_tag().constructed(), |cert| -> EncResult {
                cert.write_tagged_object(TAG_CERTIFICATE_BODY.application_tag().constructed(), |body| -> EncResult {
                    body.write_tagged_object(TAG_PROFILE_IDENTIFIER.application_tag(), |field| -> EncResult {
                        field.write_bytes(&[0x00]);
                        Ok(())
                    })?;
                    body.write_tagged_object(
                        TAG_CERTIFICATION_AUTHORITY_REFERENCE.application_tag(),
                        |field| -> EncResult {
                            field.write_bytes(b"CAR");
                            Ok(())
                        },
                    )?;
                    body.write_tagged_object(TAG_PUBLIC_KEY.application_tag().constructed(), |field| -> EncResult {
                        let oid = ObjectIdentifier::parse("1.2.3.4").expect("valid OID");
                        field.write_object_identifier(&oid)?;
                        field.write_bytes(public_key);
                        Ok(())
                    })?;
                    body.write_tagged_object(
                        TAG_CERTIFICATE_HOLDER_REFERENCE.application_tag(),
                        |field| -> EncResult {
                            field.write_bytes(b"CHR");
                            Ok(())
                        },
                    )?;
                    body.write_tagged_object(TAG_CHAT.application_tag().constructed(), |chat| -> EncResult {
                        let oid = ObjectIdentifier::parse("1.2.3").expect("valid OID");
                        chat.write_object_identifier(&oid)?;
                        chat.write_tagged_object(TAG_DISCRETIONARY_DATA.application_tag(), |data| -> EncResult {
                            data.write_bytes(&[0x00]);
                            Ok(())
                        })?;
                        Ok(())
                    })?;
                    body.write_tagged_object(TAG_CERTIFICATE_EFFECTIVE_DATE.application_tag(), |field| -> EncResult {
                        field.write_bytes(&[2, 5, 0, 1, 0, 1]);
                        Ok(())
                    })?;
                    body.write_tagged_object(
                        TAG_CERTIFICATE_EXPIRATION_DATE.application_tag(),
                        |field| -> EncResult {
                            field.write_bytes(&[2, 5, 0, 1, 0, 2]);
                            Ok(())
                        },
                    )?;
                    Ok(())
                })?;
                cert.write_tagged_object(TAG_SIGNATURE.application_tag(), |sig| -> EncResult {
                    sig.write_bytes(&[0x00]);
                    Ok(())
                })?;
                Ok(())
            })
        })
        .expect("encoding must succeed")
    }

    fn hex_to_bytes(hex_str: &str) -> Vec<u8> {
        let mut out = Vec::new();
        let mut chars = hex_str.chars().filter(|c| !c.is_whitespace()).peekable();
        while chars.peek().is_some() {
            let hi = chars.next().expect("hex high nibble");
            let lo = chars.next().expect("hex low nibble");
            let byte = u8::from_str_radix(&format!("{hi}{lo}"), 16).expect("valid hex");
            out.push(byte);
        }
        out
    }

    #[test]
    fn parse_cv_certificate_without_extensions() {
        let data = build_test_certificate(false);
        let cert = CVCertificate::parse(&data).expect("parse should succeed");

        assert_eq!(cert.body.profile_identifier, 0);
        assert_eq!(cert.body.certification_authority_reference, b"CAR");
        assert_eq!(cert.body.public_key.key_oid.to_string(), "1.2.3.4");
        assert_eq!(cert.body.public_key.key_data, vec![0xA0, 0x01, 0x02]);
        assert_eq!(cert.body.certificate_holder_reference, b"CH");
        let chat = &cert.body.certificate_holder_authorization_template;
        assert_eq!(chat.terminal_type.to_string(), "1.2.3");
        assert_eq!(chat.relative_authorization, vec![0xAA, 0xBB]);
        assert_eq!(cert.body.certificate_effective_date, CertificateDate { year: 25, month: 1, day: 1 });
        assert_eq!(cert.body.certificate_expiration_date, CertificateDate { year: 26, month: 12, day: 31 });
        assert!(cert.body.certificate_extensions.is_none());
        assert_eq!(cert.signature, vec![0xDE, 0xAD]);
    }

    #[test]
    fn parse_cv_certificate_with_extensions() {
        let data = build_test_certificate(true);
        let cert = CVCertificate::parse(&data).expect("parse should succeed");
        let extensions = cert.body.certificate_extensions.expect("extensions should be present");

        assert_eq!(extensions.templates.len(), 1);
        let template = &extensions.templates[0];
        assert_eq!(template.extension_id.to_string(), "1.2.3.4");
        assert_eq!(template.extension_data.len(), 2);
        assert_eq!(template.extension_data[0].tag, 0u8.context_tag());
        assert_eq!(template.extension_data[0].value, vec![0x10]);
        assert_eq!(template.extension_data[1].tag, 1u8.context_tag());
        assert_eq!(template.extension_data[1].value, vec![0x20, 0x30]);
    }

    #[test]
    fn parse_cv_certificate_from_pycvc_fixture() {
        let hex_data = "\
            7f218202627f4e8201585f2901004207544553544341527f49820115060a04007f000702020201\
            0281820100c1195824540bdeabbb33293c25d18eaf2afd8a3a546af0941105a9676e82046be6ea\
            0e0be0a32832e9d0f55ea81de640f7097f8ec5ef8170a22469f0fa99f63e9aa35a2bcf73e837bbc\
            13c9650f005dd9215a3046eb7db7e50e9b7a9d99d87736d08c0bbf7eae9f7a5c8e9b52e4de29be\
            28682b3ed1443a30238132ea43d5ae69dcd450dcc09d4626102a1cbc2bbe3423169fbb6ca45cc52\
            d7930e28da53ab2eabf0f869471db512b614a7397a673b7228f11b851a8b0a3eb48ed762651a323\
            f4b907ef8d216f5cc028f6ead6b79b6229a6c075d266f4f726ae6a44ff1471f1066cd7ef1f17ecf\
            ed620ed3af4771085175eb85df2ba06ba437beb0a676380a4982030100015f200754455354434852\
            7f4c12060904007f000703010202530500000003005f25060205000100015f24060205000103015f\
            378201007ecf161d4146d0015edbebf7ec3a18a46ac0cfae67a488f893018ad7958774e8fc716ed\
            349e0015d90f769d472492cbc7a010ccf81fa26ab59223047d38a2e02e6687f7b313386ac3e0ed3\
            ca4fa3c93434d86ab1fe4023fee002001b9c2aa45827e9614fb4503624a02b552d908cec1b55868\
            c68d2d646475f2b02d9db4fe9c250e64966a533b015c2faa995ea254ac08eccade344425991c122\
            0fd08db2205b72b1aa70ba538924061292a93c6420cab3d9322882f0282b7ada9a097926f566e42\
            d54f39320e29a031641aa96e91508e3176a4d554c503d7ab4942b759ee304c99668cb9e34b1eb99\
            5890aa75d7325cc9d7262d0b410b617184fad6bcc81fbd";
        let data = hex_to_bytes(hex_data);
        let cert = CVCertificate::parse(&data).expect("parse should succeed");

        assert_eq!(cert.body.profile_identifier, 0);
        assert_eq!(cert.body.certification_authority_reference, b"TESTCAR");
        assert_eq!(cert.body.public_key.key_oid.to_string(), "0.4.0.127.0.7.2.2.2.1.2");
        assert_eq!(cert.body.public_key.key_data.len(), 0x109);
        assert_eq!(cert.body.certificate_holder_reference, b"TESTCHR");
        assert_eq!(cert.body.certificate_effective_date, CertificateDate { year: 25, month: 1, day: 1 });
        assert_eq!(cert.body.certificate_expiration_date, CertificateDate { year: 25, month: 1, day: 31 });

        let chat = &cert.body.certificate_holder_authorization_template;
        assert_eq!(chat.terminal_type.to_string(), "0.4.0.127.0.7.3.1.2.2");
        assert_eq!(chat.relative_authorization, vec![0x00, 0x00, 0x00, 0x03, 0x00]);
    }

    #[test]
    fn parse_cv_certificate_from_egk_aut_cvc_e256() {
        let hex_data = "\
            7f2181da7f4e81935f290170420844454758581102237f494b06062b24030503\
            018641045e7ae614740e7012e350de71c10021ec668f21d6859591b4f709c4c7\
            3cce91c5a7fb0be1327e59ff1d0cb402b9c2bb0dc0432fa566bd4ff5f532258c\
            7364aecd5f200c0009802768831100001565497f4c1306082a8214004c048118\
            5307000000000000005f25060204000400025f24060209000400015f37409d24\
            4d497832172304f298bd49f91f45bf346cb306adeb44b0742017a074902146cc\
            cbdbb35426c2eb602d38253d92ebe1ac6905f388407398a474c4ea612d84";
        let data = hex_to_bytes(hex_data);
        let cert = CVCertificate::parse(&data).expect("parse should succeed");

        assert_eq!(cert.body.profile_identifier, 0x70);
        assert_eq!(cert.body.certification_authority_reference, vec![0x44, 0x45, 0x47, 0x58, 0x58, 0x11, 0x02, 0x23]);
        assert_eq!(
            cert.body.certificate_holder_reference,
            vec![0x00, 0x09, 0x80, 0x27, 0x68, 0x83, 0x11, 0x00, 0x00, 0x15, 0x65, 0x49]
        );
        assert_eq!(cert.body.certificate_holder_authorization_template.terminal_type.to_string(), "1.2.276.0.76.4.152");
        assert_eq!(
            cert.body.certificate_holder_authorization_template.relative_authorization,
            vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        );
        assert_eq!(cert.body.certificate_effective_date, CertificateDate { year: 24, month: 4, day: 2 });
        assert_eq!(cert.body.certificate_expiration_date, CertificateDate { year: 29, month: 4, day: 1 });
        assert_eq!(cert.body.public_key.key_oid.to_string(), "1.3.36.3.5.3.1");
        assert_eq!(cert.body.public_key.key_data.len(), 0x43);
        assert_eq!(cert.signature.len(), 0x40);
    }

    #[test]
    fn reject_profile_identifier_out_of_range() {
        let data =
            build_certificate_with_fields(&[0x01, 0x00], b"CAR", b"CHR", &[2, 5, 0, 1, 0, 1], &[2, 5, 0, 1, 0, 2]);
        assert!(CVCertificate::parse(&data).is_err());
    }

    #[test]
    fn reject_negative_profile_identifier() {
        let data = build_certificate_with_fields(&[0xFF], b"CAR", b"CHR", &[2, 5, 0, 1, 0, 1], &[2, 5, 0, 1, 0, 2]);
        assert!(CVCertificate::parse(&data).is_err());
    }

    #[test]
    fn reject_empty_car() {
        let data = build_certificate_with_fields(&[0x00], b"", b"CHR", &[2, 5, 0, 1, 0, 1], &[2, 5, 0, 1, 0, 2]);
        assert!(CVCertificate::parse(&data).is_err());
    }

    #[test]
    fn reject_chr_too_long() {
        let data = build_certificate_with_fields(
            &[0x00],
            b"CAR",
            b"0123456789ABCDEFG",
            &[2, 5, 0, 1, 0, 1],
            &[2, 5, 0, 1, 0, 2],
        );
        assert!(CVCertificate::parse(&data).is_err());
    }

    #[test]
    fn reject_invalid_date_length() {
        let data = build_certificate_with_fields(&[0x00], b"CAR", b"CHR", &[2, 5, 0, 1, 0], &[2, 5, 0, 1, 0, 2]);
        assert!(CVCertificate::parse(&data).is_err());
    }

    #[test]
    fn reject_invalid_date_digit() {
        let data = build_certificate_with_fields(&[0x00], b"CAR", b"CHR", &[2, 5, 10, 1, 0, 1], &[2, 5, 0, 1, 0, 2]);
        assert!(CVCertificate::parse(&data).is_err());
    }

    #[test]
    fn reject_invalid_month() {
        let data = build_certificate_with_fields(&[0x00], b"CAR", b"CHR", &[2, 5, 1, 3, 0, 1], &[2, 5, 0, 1, 0, 2]);
        assert!(CVCertificate::parse(&data).is_err());
    }

    #[test]
    fn reject_empty_public_key() {
        let data = build_certificate_with_public_key(&[]);
        assert!(CVCertificate::parse(&data).is_err());
    }

    #[test]
    fn allow_empty_chat_data() {
        let data = build_certificate_with_chat_data(&[]);
        let cert = CVCertificate::parse(&data).expect("parse should succeed");
        assert!(cert.body.certificate_holder_authorization_template.relative_authorization.is_empty());
    }

    #[test]
    fn allow_empty_signature() {
        let data = build_certificate_with_fields_and_signature(
            &[0x00],
            b"CAR",
            b"CHR",
            &[2, 5, 0, 1, 0, 1],
            &[2, 5, 0, 1, 0, 2],
            &[],
        );
        let cert = CVCertificate::parse(&data).expect("parse should succeed");
        assert!(cert.signature.is_empty());
    }
}
