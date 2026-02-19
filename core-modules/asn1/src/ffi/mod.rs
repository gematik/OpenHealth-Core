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

//! UniFFI bindings for `asn1`.
//!
//! This module defines the Rust-side surface that is exported via UniFFI to foreign languages.
//! It intentionally exposes a small, FFI-friendly API and record graph.
//!
//! See `core-modules/asn1/src/ffi/README.md` for an overview of the exported API.

use crate::tag::{Asn1Class as CoreAsn1Class, Asn1Form as CoreAsn1Form, Asn1Id as CoreAsn1Id};
use thiserror::Error;

/// FFI-friendly tag form (`primitive` vs `constructed`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum Asn1TagForm {
    Primitive,
    Constructed,
}

impl From<CoreAsn1Form> for Asn1TagForm {
    fn from(value: CoreAsn1Form) -> Self {
        match value {
            CoreAsn1Form::Primitive => Asn1TagForm::Primitive,
            CoreAsn1Form::Constructed => Asn1TagForm::Constructed,
        }
    }
}

/// FFI-friendly tag class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum Asn1TagClass {
    Universal,
    Application,
    ContextSpecific,
    Private,
}

impl From<CoreAsn1Class> for Asn1TagClass {
    fn from(value: CoreAsn1Class) -> Self {
        match value {
            CoreAsn1Class::Universal => Asn1TagClass::Universal,
            CoreAsn1Class::Application => Asn1TagClass::Application,
            CoreAsn1Class::ContextSpecific => Asn1TagClass::ContextSpecific,
            CoreAsn1Class::Private => Asn1TagClass::Private,
        }
    }
}

/// FFI-friendly ASN.1 tag representation.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct Asn1Tag {
    pub class_: Asn1TagClass,
    pub form: Asn1TagForm,
    pub number: u32,
}

impl From<CoreAsn1Id> for Asn1Tag {
    fn from(value: CoreAsn1Id) -> Self {
        Self { class_: value.class.into(), form: value.form.into(), number: value.number }
    }
}

/// Parsed CV certificate (application tag `7F21`).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct CvCertificate {
    pub body: CvCertificateBody,
    pub signature: Vec<u8>,
}

impl From<crate::cv_certificate::CVCertificate> for CvCertificate {
    fn from(value: crate::cv_certificate::CVCertificate) -> Self {
        Self { body: value.body.into(), signature: value.signature }
    }
}

/// Parsed CV certificate body.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct CvCertificateBody {
    pub profile_identifier: u8,
    pub certification_authority_reference: Vec<u8>,
    pub public_key: CvPublicKey,
    pub certificate_holder_reference: Vec<u8>,
    pub certificate_holder_authorization_template: CvChat,
    pub certificate_effective_date: CvCertificateDate,
    pub certificate_expiration_date: CvCertificateDate,
    pub certificate_extensions: Option<CvCertificateExtensions>,
}

impl From<crate::cv_certificate::CertificateBody> for CvCertificateBody {
    fn from(value: crate::cv_certificate::CertificateBody) -> Self {
        Self {
            profile_identifier: value.profile_identifier,
            certification_authority_reference: value.certification_authority_reference,
            public_key: value.public_key.into(),
            certificate_holder_reference: value.certificate_holder_reference,
            certificate_holder_authorization_template: value.certificate_holder_authorization_template.into(),
            certificate_effective_date: value.certificate_effective_date.into(),
            certificate_expiration_date: value.certificate_expiration_date.into(),
            certificate_extensions: value.certificate_extensions.map(Into::into),
        }
    }
}

/// CV certificate public key information.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct CvPublicKey {
    pub key_oid: String,
    pub key_data: Vec<u8>,
}

impl From<crate::cv_certificate::CVCertPublicKey> for CvPublicKey {
    fn from(value: crate::cv_certificate::CVCertPublicKey) -> Self {
        Self { key_oid: value.key_oid.to_string(), key_data: value.key_data }
    }
}

/// Certificate Holder Authorization Template (CHAT).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct CvChat {
    pub terminal_type_oid: String,
    pub relative_authorization: Vec<u8>,
}

impl From<crate::cv_certificate::Chat> for CvChat {
    fn from(value: crate::cv_certificate::Chat) -> Self {
        Self { terminal_type_oid: value.terminal_type.to_string(), relative_authorization: value.relative_authorization }
    }
}

/// A CVC date encoded as digits `YYMMDD`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct CvCertificateDate {
    pub year: u8,
    pub month: u8,
    pub day: u8,
}

impl From<crate::cv_certificate::CertificateDate> for CvCertificateDate {
    fn from(value: crate::cv_certificate::CertificateDate) -> Self {
        Self { year: value.year, month: value.month, day: value.day }
    }
}

/// Optional extensions carried in the certificate body.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct CvCertificateExtensions {
    pub templates: Vec<CvDiscretionaryDataTemplate>,
}

impl From<crate::cv_certificate::CertificateExtensions> for CvCertificateExtensions {
    fn from(value: crate::cv_certificate::CertificateExtensions) -> Self {
        Self { templates: value.templates.into_iter().map(Into::into).collect() }
    }
}

/// One discretionary data template within [`CvCertificateExtensions`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct CvDiscretionaryDataTemplate {
    pub extension_id_oid: String,
    pub extension_data: Vec<CvExtensionField>,
}

impl From<crate::cv_certificate::DiscretionaryDataTemplate> for CvDiscretionaryDataTemplate {
    fn from(value: crate::cv_certificate::DiscretionaryDataTemplate) -> Self {
        Self {
            extension_id_oid: value.extension_id.to_string(),
            extension_data: value.extension_data.into_iter().map(Into::into).collect(),
        }
    }
}

/// A raw extension field inside a discretionary data template.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct CvExtensionField {
    pub tag: Asn1Tag,
    pub value: Vec<u8>,
}

impl From<crate::cv_certificate::ExtensionField> for CvExtensionField {
    fn from(value: crate::cv_certificate::ExtensionField) -> Self {
        Self { tag: value.tag.into(), value: value.value }
    }
}

/// UniFFI error type for `asn1` operations.
#[derive(Debug, Clone, Error)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Error))]
pub enum Asn1FfiError {
    #[error("ASN.1 decode error: {reason}")]
    Decode { reason: String },
    #[error("invalid argument: {reason}")]
    InvalidArgument { reason: String },
}

#[uniffi::export]
pub fn parse_cv_certificate(data: Vec<u8>) -> Result<CvCertificate, Asn1FfiError> {
    if data.is_empty() {
        return Err(Asn1FfiError::InvalidArgument { reason: "data must not be empty".into() });
    }
    let cert = crate::cv_certificate::parse_cv_certificate(&data)
        .map_err(|err| Asn1FfiError::Decode { reason: err.to_string() })?;
    Ok(cert.into())
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn parse_cv_certificate_maps_key_fields() {
        let hex_data = "\
            7f2181da7f4e81935f290170420844454758581102237f494b06062b24030503\
            018641045e7ae614740e7012e350de71c10021ec668f21d6859591b4f709c4c7\
            3cce91c5a7fb0be1327e59ff1d0cb402b9c2bb0dc0432fa566bd4ff5f532258c\
            7364aecd5f200c0009802768831100001565497f4c1306082a8214004c048118\
            5307000000000000005f25060204000400025f24060209000400015f37409d24\
            4d497832172304f298bd49f91f45bf346cb306adeb44b0742017a074902146cc\
            cbdbb35426c2eb602d38253d92ebe1ac6905f388407398a474c4ea612d84";
        let bytes = hex_to_bytes(hex_data);
        let cert = parse_cv_certificate(bytes).expect("parse should succeed");

        assert_eq!(cert.body.profile_identifier, 0x70);
        assert_eq!(cert.body.public_key.key_oid, "1.3.36.3.5.3.1");
        assert_eq!(cert.body.certificate_holder_authorization_template.terminal_type_oid, "1.2.276.0.76.4.152");
        assert_eq!(cert.body.certificate_effective_date, CvCertificateDate { year: 24, month: 4, day: 2 });
        assert_eq!(cert.body.certificate_expiration_date, CvCertificateDate { year: 29, month: 4, day: 1 });
    }

    #[test]
    fn tag_mapping_preserves_fields() {
        let id = crate::tag::Asn1Id::ctx(1).constructed();
        let tag: Asn1Tag = id.into();
        assert_eq!(tag.class_, Asn1TagClass::ContextSpecific);
        assert_eq!(tag.form, Asn1TagForm::Constructed);
        assert_eq!(tag.number, 1);
    }

    #[test]
    fn error_mapping_uses_decode_variant() {
        let err = parse_cv_certificate(vec![0x00]).unwrap_err();
        match err {
            Asn1FfiError::Decode { reason } => assert!(!reason.is_empty()),
            other => panic!("expected Decode error, got {other:?}"),
        }
    }
}

