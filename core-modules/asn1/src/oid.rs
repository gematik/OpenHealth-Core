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

use crate::error::{Asn1DecoderError, Asn1EncoderError};
use core::fmt;
use core::str::FromStr;

/// Strongly typed ASN.1 object identifier.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ObjectIdentifier(Vec<u32>);

impl ObjectIdentifier {
    /// Construct an OID from dot-separated string.
    pub fn parse(value: &str) -> Result<Self, Asn1EncoderError> {
        let parts: Vec<u32> = value
            .split('.')
            .map(|p| p.parse::<u32>().map_err(|_| Asn1EncoderError::invalid_object_identifier_part(p)))
            .collect::<Result<_, _>>()?;
        Self::from_components_for_encoding(parts)
    }

    /// Construct an OID from raw components for encoder use.
    pub fn from_components_for_encoding(parts: Vec<u32>) -> Result<Self, Asn1EncoderError> {
        validate_parts_encoder(&parts)?;
        Ok(Self(parts))
    }

    /// Construct an OID from decoded components.
    pub fn from_components_for_decoding(parts: Vec<u32>) -> Result<Self, Asn1DecoderError> {
        validate_parts_decoder(&parts)?;
        Ok(Self(parts))
    }

    /// Return OID components.
    pub fn components(&self) -> &[u32] {
        &self.0
    }
}

impl fmt::Debug for ObjectIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self)
    }
}

impl fmt::Display for ObjectIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut iter = self.0.iter();
        if let Some(first) = iter.next() {
            write!(f, "{first}")?;
        }
        for part in iter {
            write!(f, ".{part}")?;
        }
        Ok(())
    }
}

impl FromStr for ObjectIdentifier {
    type Err = Asn1EncoderError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

fn validate_parts_encoder(parts: &[u32]) -> Result<(), Asn1EncoderError> {
    if parts.len() < 2 {
        return Err(Asn1EncoderError::object_identifier_missing_components());
    }
    let first = parts[0] as i32;
    let second = parts[1] as i32;
    if !(0..=2).contains(&first) {
        return Err(Asn1EncoderError::invalid_object_identifier_first_component(first));
    }
    if first < 2 && !(0..=39).contains(&second) {
        return Err(Asn1EncoderError::invalid_object_identifier_second_component(second));
    }
    Ok(())
}

fn validate_parts_decoder(parts: &[u32]) -> Result<(), Asn1DecoderError> {
    if parts.len() < 2 {
        return Err(Asn1DecoderError::EmptyObjectIdentifier);
    }
    let first = parts[0] as i32;
    let second = parts[1] as i32;
    if first < 0 {
        return Err(Asn1DecoderError::Custom { message: "invalid OID first component".into() });
    }
    if first < 2 && !(0..=39).contains(&second) {
        return Err(Asn1DecoderError::Custom { message: "invalid OID second component".into() });
    }
    Ok(())
}
