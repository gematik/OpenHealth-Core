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
//! It intentionally exposes a small, FFI-friendly API and object graph.
//!
//! See `core-modules/asn1/src/ffi/README.md` for an overview of the exported API.

use crate::decoder::{Asn1Decoder, Asn1Length};
use crate::encoder::Asn1Encoder;
use crate::error::Asn1EncoderError;
use crate::tag::{Asn1Class as CoreAsn1Class, Asn1Form as CoreAsn1Form, Asn1Id as CoreAsn1Id};
use std::sync::Arc;
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
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct Asn1Tag {
    class_: Asn1TagClass,
    form: Asn1TagForm,
    number: u32,
}

impl From<CoreAsn1Id> for Asn1Tag {
    fn from(value: CoreAsn1Id) -> Self {
        Self { class_: value.class.into(), form: value.form.into(), number: value.number }
    }
}

#[uniffi::export]
impl Asn1Tag {
    pub fn class_(&self) -> Asn1TagClass {
        self.class_
    }

    pub fn form(&self) -> Asn1TagForm {
        self.form
    }

    pub fn number(&self) -> u32 {
        self.number
    }
}

impl From<Asn1Tag> for CoreAsn1Id {
    fn from(value: Asn1Tag) -> Self {
        let class = match value.class_ {
            Asn1TagClass::Universal => CoreAsn1Class::Universal,
            Asn1TagClass::Application => CoreAsn1Class::Application,
            Asn1TagClass::ContextSpecific => CoreAsn1Class::ContextSpecific,
            Asn1TagClass::Private => CoreAsn1Class::Private,
        };
        let form = match value.form {
            Asn1TagForm::Primitive => CoreAsn1Form::Primitive,
            Asn1TagForm::Constructed => CoreAsn1Form::Constructed,
        };
        CoreAsn1Id::new(class, form, value.number)
    }
}

/// Parsed CV certificate (application tag `7F21`).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct CvCertificate {
    inner: crate::cv_certificate::CVCertificate,
}

impl From<crate::cv_certificate::CVCertificate> for CvCertificate {
    fn from(value: crate::cv_certificate::CVCertificate) -> Self {
        Self { inner: value }
    }
}

impl CvCertificate {
    pub fn as_core(&self) -> &crate::cv_certificate::CVCertificate {
        &self.inner
    }
}

#[uniffi::export]
impl CvCertificate {
    pub fn body(&self) -> Arc<CvCertificateBody> {
        Arc::new(self.inner.body.clone().into())
    }

    pub fn signature(&self) -> Vec<u8> {
        self.inner.signature.to_vec()
    }

    pub fn encoded_certificate_tlv(&self) -> Vec<u8> {
        self.inner.encoded_certificate_tlv().to_vec()
    }

    pub fn encoded_body_tlv(&self) -> Vec<u8> {
        self.inner.encoded_body_tlv().to_vec()
    }

    pub fn encoded_public_key_tlv(&self) -> Vec<u8> {
        self.inner.encoded_public_key_tlv().to_vec()
    }

    pub fn encoded_signature_tlv(&self) -> Vec<u8> {
        self.inner.encoded_signature_tlv().to_vec()
    }
}

/// Parsed CV certificate body.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct CvCertificateBody {
    profile_identifier: u8,
    certification_authority_reference: Vec<u8>,
    public_key: CvPublicKey,
    certificate_holder_reference: Vec<u8>,
    certificate_holder_authorization_template: CvChat,
    certificate_effective_date: CvCertificateDate,
    certificate_expiration_date: CvCertificateDate,
    certificate_extensions: Option<CvCertificateExtensions>,
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

#[uniffi::export]
impl CvCertificateBody {
    pub fn profile_identifier(&self) -> u8 {
        self.profile_identifier
    }

    pub fn certification_authority_reference(&self) -> Vec<u8> {
        self.certification_authority_reference.clone()
    }

    pub fn public_key(&self) -> Arc<CvPublicKey> {
        Arc::new(self.public_key.clone())
    }

    pub fn certificate_holder_reference(&self) -> Vec<u8> {
        self.certificate_holder_reference.clone()
    }

    pub fn certificate_holder_authorization_template(&self) -> Arc<CvChat> {
        Arc::new(self.certificate_holder_authorization_template.clone())
    }

    pub fn certificate_effective_date(&self) -> Arc<CvCertificateDate> {
        Arc::new(self.certificate_effective_date)
    }

    pub fn certificate_expiration_date(&self) -> Arc<CvCertificateDate> {
        Arc::new(self.certificate_expiration_date)
    }

    pub fn certificate_extensions(&self) -> Option<Arc<CvCertificateExtensions>> {
        self.certificate_extensions.clone().map(Arc::new)
    }
}

/// CV certificate public key information.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct CvPublicKey {
    key_oid: String,
    key_data: Vec<u8>,
}

impl From<crate::cv_certificate::CVCertPublicKey> for CvPublicKey {
    fn from(value: crate::cv_certificate::CVCertPublicKey) -> Self {
        Self { key_oid: value.key_oid.to_string(), key_data: value.key_data }
    }
}

#[uniffi::export]
impl CvPublicKey {
    pub fn key_oid(&self) -> String {
        self.key_oid.clone()
    }

    pub fn key_data(&self) -> Vec<u8> {
        self.key_data.clone()
    }
}

/// Certificate Holder Authorization Template (CHAT).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct CvChat {
    terminal_type_oid: String,
    relative_authorization: Vec<u8>,
}

impl From<crate::cv_certificate::Chat> for CvChat {
    fn from(value: crate::cv_certificate::Chat) -> Self {
        Self {
            terminal_type_oid: value.terminal_type.to_string(),
            relative_authorization: value.relative_authorization,
        }
    }
}

#[uniffi::export]
impl CvChat {
    pub fn terminal_type_oid(&self) -> String {
        self.terminal_type_oid.clone()
    }

    pub fn relative_authorization(&self) -> Vec<u8> {
        self.relative_authorization.clone()
    }
}

/// A CVC date encoded as digits `YYMMDD`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct CvCertificateDate {
    year: u8,
    month: u8,
    day: u8,
}

impl From<crate::cv_certificate::CertificateDate> for CvCertificateDate {
    fn from(value: crate::cv_certificate::CertificateDate) -> Self {
        Self { year: value.year, month: value.month, day: value.day }
    }
}

#[uniffi::export]
impl CvCertificateDate {
    pub fn year(&self) -> u8 {
        self.year
    }

    pub fn month(&self) -> u8 {
        self.month
    }

    pub fn day(&self) -> u8 {
        self.day
    }
}

/// Optional extensions carried in the certificate body.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct CvCertificateExtensions {
    templates: Vec<CvDiscretionaryDataTemplate>,
}

impl From<crate::cv_certificate::CertificateExtensions> for CvCertificateExtensions {
    fn from(value: crate::cv_certificate::CertificateExtensions) -> Self {
        Self { templates: value.templates.into_iter().map(Into::into).collect() }
    }
}

#[uniffi::export]
impl CvCertificateExtensions {
    pub fn templates(&self) -> Vec<Arc<CvDiscretionaryDataTemplate>> {
        self.templates.iter().cloned().map(Arc::new).collect()
    }
}

/// One discretionary data template within [`CvCertificateExtensions`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct CvDiscretionaryDataTemplate {
    extension_id_oid: String,
    extension_data: Vec<CvExtensionField>,
}

impl From<crate::cv_certificate::DiscretionaryDataTemplate> for CvDiscretionaryDataTemplate {
    fn from(value: crate::cv_certificate::DiscretionaryDataTemplate) -> Self {
        Self {
            extension_id_oid: value.extension_id.to_string(),
            extension_data: value.extension_data.into_iter().map(Into::into).collect(),
        }
    }
}

#[uniffi::export]
impl CvDiscretionaryDataTemplate {
    pub fn extension_id_oid(&self) -> String {
        self.extension_id_oid.clone()
    }

    pub fn extension_data(&self) -> Vec<Arc<CvExtensionField>> {
        self.extension_data.iter().cloned().map(Arc::new).collect()
    }
}

/// A raw extension field inside a discretionary data template.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct CvExtensionField {
    tag: Asn1Tag,
    value: Vec<u8>,
}

impl From<crate::cv_certificate::ExtensionField> for CvExtensionField {
    fn from(value: crate::cv_certificate::ExtensionField) -> Self {
        Self { tag: value.tag.into(), value: value.value }
    }
}

#[uniffi::export]
impl CvExtensionField {
    pub fn tag(&self) -> Arc<Asn1Tag> {
        Arc::new(self.tag.clone())
    }

    pub fn value(&self) -> Vec<u8> {
        self.value.clone()
    }
}

/// UniFFI error type for `asn1` operations.
#[derive(Debug, Clone, Error)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Error))]
pub enum Asn1FfiError {
    #[error("ASN.1 decode error: {reason}")]
    Decode { reason: String },
    #[error("ASN.1 encode error: {reason}")]
    Encode { reason: String },
    #[error("invalid argument: {reason}")]
    InvalidArgument { reason: String },
}

#[uniffi::export]
pub fn parse_cv_certificate(data: Vec<u8>) -> Result<Arc<CvCertificate>, Asn1FfiError> {
    if data.is_empty() {
        return Err(Asn1FfiError::InvalidArgument { reason: "data must not be empty".into() });
    }
    let cert = crate::cv_certificate::parse_cv_certificate(&data)
        .map_err(|err| Asn1FfiError::Decode { reason: err.to_string() })?;
    Ok(Arc::new(cert.into()))
}

#[uniffi::export]
pub fn write_tagged_object(
    class_: Asn1TagClass,
    form: Asn1TagForm,
    number: i32,
    value: Vec<u8>,
) -> Result<Vec<u8>, Asn1FfiError> {
    let number = u32::try_from(number)
        .map_err(|_| Asn1FfiError::InvalidArgument { reason: "tag number must be non-negative".into() })?;
    let encoded = Asn1Encoder::write_nonzeroizing(|writer| {
        writer.write_tagged_object(
            CoreAsn1Id::new(class_.into(), form.into(), number),
            |inner| -> Result<(), Asn1EncoderError> {
                inner.write_bytes(&value);
                Ok(())
            },
        )
    })
    .map_err(|err| Asn1FfiError::Encode { reason: err.to_string() })?;
    Ok(encoded.to_vec())
}

#[uniffi::export]
pub fn read_tagged_object_value(
    data: Vec<u8>,
    class_: Asn1TagClass,
    form: Asn1TagForm,
    number: i32,
) -> Result<Vec<u8>, Asn1FfiError> {
    if data.is_empty() {
        return Err(Asn1FfiError::InvalidArgument { reason: "data must not be empty".into() });
    }
    let number = u32::try_from(number)
        .map_err(|_| Asn1FfiError::InvalidArgument { reason: "tag number must be non-negative".into() })?;
    Asn1Decoder::new(&data).read(|scope| {
        while scope.remaining_length() > 0 {
            let tag = scope.read_tag().map_err(Asn1FfiError::from)?;
            let length = scope.read_length().map_err(Asn1FfiError::from)?;
            let value = match length {
                Asn1Length::Definite(length) => scope.read_bytes(length).map_err(Asn1FfiError::from)?,
                Asn1Length::Indefinite => {
                    return Err(Asn1FfiError::Decode { reason: "indefinite lengths are not supported".into() });
                }
            };
            if tag.class == class_.into() && tag.form == form.into() && tag.number == number {
                return Ok(value);
            }
        }
        Err(Asn1FfiError::Decode { reason: "matching tagged object not found".into() })
    })
}

impl From<crate::error::Asn1DecoderError> for Asn1FfiError {
    fn from(value: crate::error::Asn1DecoderError) -> Self {
        Asn1FfiError::Decode { reason: value.to_string() }
    }
}

impl From<Asn1TagClass> for CoreAsn1Class {
    fn from(value: Asn1TagClass) -> Self {
        match value {
            Asn1TagClass::Universal => CoreAsn1Class::Universal,
            Asn1TagClass::Application => CoreAsn1Class::Application,
            Asn1TagClass::ContextSpecific => CoreAsn1Class::ContextSpecific,
            Asn1TagClass::Private => CoreAsn1Class::Private,
        }
    }
}

impl From<Asn1TagForm> for CoreAsn1Form {
    fn from(value: Asn1TagForm) -> Self {
        match value {
            Asn1TagForm::Primitive => CoreAsn1Form::Primitive,
            Asn1TagForm::Constructed => CoreAsn1Form::Constructed,
        }
    }
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

        let body = cert.body();
        assert_eq!(body.profile_identifier(), 0x70);
        assert_eq!(body.public_key().key_oid(), "1.3.36.3.5.3.1");
        assert_eq!(body.certificate_holder_authorization_template().terminal_type_oid(), "1.2.276.0.76.4.152");
        let effective_date = body.certificate_effective_date();
        assert_eq!(effective_date.year(), 24);
        assert_eq!(effective_date.month(), 4);
        assert_eq!(effective_date.day(), 2);
        let expiration_date = body.certificate_expiration_date();
        assert_eq!(expiration_date.year(), 29);
        assert_eq!(expiration_date.month(), 4);
        assert_eq!(expiration_date.day(), 1);
    }

    #[test]
    fn tag_mapping_preserves_fields() {
        let id = crate::tag::Asn1Id::ctx(1).constructed();
        let tag: Asn1Tag = id.into();
        assert_eq!(tag.class_(), Asn1TagClass::ContextSpecific);
        assert_eq!(tag.form(), Asn1TagForm::Constructed);
        assert_eq!(tag.number(), 1);
    }

    #[test]
    fn error_mapping_uses_decode_variant() {
        let err = parse_cv_certificate(vec![0x00]).unwrap_err();
        match err {
            Asn1FfiError::Decode { reason } => assert!(!reason.is_empty()),
            other => panic!("expected Decode error, got {other:?}"),
        }
    }

    #[test]
    fn read_tagged_object_value_reads_constructed_child_value() {
        let value = read_tagged_object_value(
            hex_to_bytes("85 02 12 34"),
            Asn1TagClass::ContextSpecific,
            Asn1TagForm::Primitive,
            0x05,
        )
        .expect("read should succeed");
        assert_eq!(value, hex_to_bytes("12 34"));
    }

    #[test]
    fn write_tagged_object_encodes_expected_bytes() {
        let tlv =
            write_tagged_object(Asn1TagClass::ContextSpecific, Asn1TagForm::Primitive, 0x01, hex_to_bytes("90 00"))
                .unwrap();
        assert_eq!(tlv, hex_to_bytes("81 02 90 00"));
    }

    #[test]
    fn write_tagged_object_constructed_encodes_expected_bytes() {
        let tlv = write_tagged_object(
            Asn1TagClass::ContextSpecific,
            Asn1TagForm::Constructed,
            0x1C,
            hex_to_bytes("85 02 04 05"),
        )
        .unwrap();
        assert_eq!(tlv, hex_to_bytes("BC 04 85 02 04 05"));
    }

    #[test]
    fn read_tagged_object_value_reads_real_world_application_7c_value() {
        let value = read_tagged_object_value(
            hex_to_bytes(
                "7C 43 85 41 04 2B E9 58 49 26 7F 76 4D EF 49 F0 38 92 A5 14 7D 94 FF C4 30 A5 39 E7 D2 F7 08 29 6E C3 FE A3 47 54 CC 4B 1C 27 70 C6 85 42 7F F3 45 5C 84 AA 81 B8 2D 17 66 35 3D 49 C6 A7 19 84 7F 49 87 49 50",
            ),
            Asn1TagClass::Application,
            Asn1TagForm::Constructed,
            0x1C,
        )
        .expect("read should succeed");
        assert_eq!(
            value,
            hex_to_bytes(
                "85 41 04 2B E9 58 49 26 7F 76 4D EF 49 F0 38 92 A5 14 7D 94 FF C4 30 A5 39 E7 D2 F7 08 29 6E C3 FE A3 47 54 CC 4B 1C 27 70 C6 85 42 7F F3 45 5C 84 AA 81 B8 2D 17 66 35 3D 49 C6 A7 19 84 7F 49 87 49 50"
            )
        );
    }
}
