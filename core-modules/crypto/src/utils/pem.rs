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

use std::sync::OnceLock;

use base64::Engine;
use regex::Regex;
use thiserror::Error;

const PEM_DATA_MAX_LENGTH_PER_LINE: usize = 64;

static PEM_REGEX: OnceLock<Regex> = OnceLock::new();

/// Represents a Privacy Enhanced Mail (PEM) formatted cryptographic object.
pub struct Pem {
    pub r#type: String,
    pub data: Vec<u8>,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum PemError {
    #[error("invalid PEM format")]
    InvalidFormat,
    #[error("PEM header/footer mismatch: {header} vs {footer}")]
    TypeMismatch { header: String, footer: String },
    #[error("Base64 decoding failed")]
    Base64,
}

/// Encodes the PEM object into its string representation
/// with BEGIN/END markers and Base64-encoded data.
impl Pem {
    pub fn encode_to_string(&self) -> String {
        let mut result = String::new();
        result.push_str(&format!("-----BEGIN {}-----\n", self.r#type));
        let encoded = base64::engine::general_purpose::STANDARD.encode(&self.data);
        for chunk in encoded.as_bytes().chunks(PEM_DATA_MAX_LENGTH_PER_LINE) {
            result.push_str(&format!("{}\n", String::from_utf8_lossy(chunk)));
        }
        result.push_str(&format!("-----END {}-----\n", self.r#type));
        result
    }
}

/// Decodes a PEM-formatted string into a `Pem` object.
pub trait DecodeToPem {
    fn decode_to_pem(&self) -> Result<Pem, PemError>;
}

impl DecodeToPem for str {
    fn decode_to_pem(&self) -> Result<Pem, PemError> {
        let s = self.replace('\n', "").trim().to_owned();
        let re = PEM_REGEX
            .get_or_init(|| Regex::new(r"^-----BEGIN (.*)-----(.*)-----END (.*)-----$").expect("compile PEM regex"));
        let Some(captures) = re.captures(&s) else {
            return Err(PemError::InvalidFormat);
        };
        let header_type = captures.get(1).map(|m| m.as_str()).ok_or(PemError::InvalidFormat)?;
        let data = captures.get(2).map(|m| m.as_str()).ok_or(PemError::InvalidFormat)?;
        let footer_type = captures.get(3).map(|m| m.as_str()).ok_or(PemError::InvalidFormat)?;
        if header_type != footer_type {
            return Err(PemError::TypeMismatch { header: header_type.to_string(), footer: footer_type.to_string() });
        }
        let decoded = base64::engine::general_purpose::STANDARD.decode(data).map_err(|_| PemError::Base64)?;
        Ok(Pem { r#type: header_type.to_string(), data: decoded })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_and_decode_pem_with_short_data() {
        let typ = "TEST CERTIFICATE";
        let data = b"Hello World".to_vec();
        let pem = Pem { r#type: typ.to_string(), data: data.clone() };

        let encoded = pem.encode_to_string();
        let decoded = encoded.decode_to_pem().unwrap();

        assert_eq!(typ, decoded.r#type);
        assert_eq!(data, decoded.data);
    }

    #[test]
    fn encode_and_decode_pem_with_long_data() {
        let typ = "LONG CERTIFICATE";
        let data: Vec<u8> = (0..100).collect();
        let pem = Pem { r#type: typ.to_string(), data: data.clone() };

        let encoded = pem.encode_to_string();
        let decoded = encoded.decode_to_pem().unwrap();

        assert_eq!(typ, decoded.r#type);
        assert_eq!(data, decoded.data);
        assert!(encoded.contains('\n'));
    }

    #[test]
    fn encode_pem_respects_line_length_limit() {
        let typ = "TEST";
        let data = vec![65u8; 100]; // 100 x 'A'
        let pem = Pem { r#type: typ.to_string(), data };

        // Insert an internal empty line so the `filter` predicate also exercises the `is_empty()` branch.
        let header = format!("-----BEGIN {typ}-----\n");
        let header_with_blank = format!("-----BEGIN {typ}-----\n\n");
        let encoded = pem.encode_to_string().replacen(&header, &header_with_blank, 1);
        let lines: Vec<&str> = encoded.lines().collect();
        assert!(lines.iter().any(|line| line.is_empty()));

        for line in lines.iter().filter(|l| !l.is_empty() && !l.starts_with("-----")) {
            assert!(line.len() <= 64, "Line exceeds 64 characters: {line}");
        }
    }

    #[test]
    fn encode_pem_ignores_empty_lines_in_length_check() {
        let typ = "TEST";
        let data = vec![65u8; 10];
        let pem = Pem { r#type: typ.to_string(), data };

        let mut encoded = pem.encode_to_string();
        encoded.push('\n');
        encoded.push('\n');
        let lines: Vec<&str> = encoded.lines().collect();

        for line in lines.iter().filter(|l| !l.is_empty() && !l.starts_with("-----")) {
            assert!(line.len() <= 64, "Line exceeds 64 characters: {line}");
        }
    }

    #[test]
    fn encode_pem_length_check_handles_internal_empty_lines() {
        let typ = "TEST";
        let data = vec![65u8; 10];
        let pem = Pem { r#type: typ.to_string(), data };

        let encoded = pem.encode_to_string().replace('\n', "\n\n");
        let lines: Vec<&str> = encoded.lines().collect();
        assert!(lines.iter().any(|line| line.is_empty()));

        for line in lines.iter().filter(|l| !l.is_empty() && !l.starts_with("-----")) {
            assert!(line.len() <= 64, "Line exceeds 64 characters: {line}");
        }
    }

    #[test]
    fn encode_pem_empty_data_has_no_payload_lines() {
        let pem = Pem { r#type: "TEST".to_string(), data: Vec::new() };
        let encoded = pem.encode_to_string();
        let lines: Vec<&str> = encoded.lines().collect();

        let payload_lines: Vec<_> = lines.iter().filter(|l| !l.is_empty() && !l.starts_with("-----")).collect();
        assert!(payload_lines.is_empty());
    }

    #[test]
    fn decode_invalid_pem_format_returns_error() {
        let invalid_pem = "Not a PEM format";
        assert!(matches!(invalid_pem.decode_to_pem(), Err(PemError::InvalidFormat)));
    }

    #[test]
    fn decode_pem_with_mismatched_types_returns_error() {
        let invalid_pem = "-----BEGIN CERT-----SGVsbG8gV29ybGQ=-----END DIFFERENT-----";
        let err = invalid_pem.decode_to_pem();
        assert!(matches!(err, Err(PemError::TypeMismatch { .. })));
    }

    #[test]
    fn decode_pem_with_whitespace_and_newlines() {
        let typ = "CERTIFICATE";
        let content = "Hello World";
        let encoded_content = base64::engine::general_purpose::STANDARD.encode(content.as_bytes());
        let pem_string = format!("-----BEGIN {typ}-----\n{encoded_content}\n-----END {typ}-----\n");

        let decoded = pem_string.decode_to_pem().unwrap();
        assert_eq!(typ, decoded.r#type);
        assert_eq!(content, String::from_utf8(decoded.data).unwrap());
    }

    #[test]
    fn encode_and_decode_empty_pem() {
        let typ = "EMPTY";
        let pem = Pem { r#type: typ.to_string(), data: Vec::new() };
        let encoded = pem.encode_to_string();
        let decoded = encoded.decode_to_pem().unwrap();
        assert_eq!(typ, decoded.r#type);
        assert!(decoded.data.is_empty());
    }
}
