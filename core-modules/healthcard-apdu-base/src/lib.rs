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

use crypto::ec::ec_key::{EcCurve, EcPrivateKey, EcPublicKey};
use crypto::error::CryptoError;
use num_bigint::{BigInt, Sign};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use thiserror::Error;

pub type EcKeyPairGenerator = Box<dyn FnMut(EcCurve) -> Result<(EcPublicKey, EcPrivateKey), CryptoError>>;

#[derive(Debug, Error)]
pub enum TranscriptError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("hex error: {0}")]
    Hex(#[from] hex::FromHexError),
    #[error("missing or invalid transcript header")]
    InvalidHeader,
    #[error("unexpected transcript entry: {0}")]
    UnexpectedEntry(&'static str),
    #[error("replay out of entries")]
    ReplayExhausted,
    #[error("invalid tx hex: {0}")]
    InvalidTxHex(String),
    #[error("invalid rx hex: {0}")]
    InvalidRxHex(String),
    #[error("replay mismatch: outgoing APDU does not match transcript")]
    ReplayMismatch,
    #[error("replayed error: {0}")]
    ReplayEntryError(String),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct TranscriptHeader {
    version: u32,
    supports_extended_length: bool,
    keys: Option<Vec<String>>,
    can: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum TranscriptEntry {
    Header { version: u32, supports_extended_length: bool, keys: Option<Vec<String>>, can: Option<String> },
    Exchange { tx: String, rx: String },
    Error { tx: String, error: String },
}

#[derive(Clone, Debug)]
pub struct Transcript {
    header: TranscriptHeader,
    entries: Vec<TranscriptEntry>,
}

impl Transcript {
    pub fn new(supports_extended_length: bool) -> Self {
        Self {
            header: TranscriptHeader { version: 1, supports_extended_length, keys: None, can: None },
            entries: Vec::new(),
        }
    }

    pub fn supports_extended_length(&self) -> bool {
        self.header.supports_extended_length
    }

    pub fn set_keys(&mut self, keys: Vec<String>) {
        self.header.keys = Some(keys);
    }

    pub fn set_can(&mut self, can: impl Into<String>) {
        self.header.can = Some(can.into());
    }

    pub fn keys(&self) -> Option<&[String]> {
        self.header.keys.as_deref()
    }

    pub fn can(&self) -> Option<&str> {
        self.header.can.as_deref()
    }

    pub fn fixed_key_generator(&self) -> Result<Option<EcKeyPairGenerator>, TranscriptError> {
        match &self.header.keys {
            Some(keys) => {
                let decoded = keys.iter().map(hex::decode).collect::<Result<Vec<_>, hex::FromHexError>>()?;
                Ok(Some(Box::new(FixedKeyGenerator::new(decoded).generator())))
            }
            None => Ok(None),
        }
    }

    pub fn push_exchange(&mut self, tx: &[u8], rx: &[u8]) {
        self.entries.push(TranscriptEntry::Exchange { tx: hex::encode_upper(tx), rx: hex::encode_upper(rx) });
    }

    pub fn push_error(&mut self, tx: &[u8], error: impl Into<String>) {
        self.entries.push(TranscriptEntry::Error { tx: hex::encode_upper(tx), error: error.into() });
    }

    pub fn to_jsonl_string(&self) -> Result<String, TranscriptError> {
        let mut out = String::new();
        let header = TranscriptEntry::Header {
            version: self.header.version,
            supports_extended_length: self.header.supports_extended_length,
            keys: self.header.keys.clone(),
            can: self.header.can.clone(),
        };
        out.push_str(&serde_json::to_string(&header)?);
        out.push('\n');
        for entry in &self.entries {
            out.push_str(&serde_json::to_string(entry)?);
            out.push('\n');
        }
        Ok(out)
    }

    pub fn write_jsonl<P: AsRef<Path>>(&self, path: P) -> Result<(), TranscriptError> {
        let mut file = File::create(path)?;
        file.write_all(self.to_jsonl_string()?.as_bytes())?;
        Ok(())
    }

    pub fn from_jsonl_str(input: &str) -> Result<Self, TranscriptError> {
        let mut lines = input.lines();
        let header_line = lines.find(|line| !line.trim().is_empty()).ok_or(TranscriptError::InvalidHeader)?;
        let header_entry: TranscriptEntry = serde_json::from_str(header_line)?;
        let header = match header_entry {
            TranscriptEntry::Header { version, supports_extended_length, keys, can } => {
                TranscriptHeader { version, supports_extended_length, keys, can }
            }
            _ => return Err(TranscriptError::InvalidHeader),
        };
        let mut entries = Vec::new();
        for line in lines {
            if line.trim().is_empty() {
                continue;
            }
            entries.push(serde_json::from_str::<TranscriptEntry>(line)?);
        }
        Ok(Self { header, entries })
    }

    pub fn from_jsonl<P: AsRef<Path>>(path: P) -> Result<Self, TranscriptError> {
        let file = File::open(path)?;
        let mut lines = BufReader::new(file).lines();
        let mut header_line = None;
        for line in &mut lines {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            header_line = Some(line);
            break;
        }
        let header_line = header_line.ok_or(TranscriptError::InvalidHeader)?;
        let header_entry: TranscriptEntry = serde_json::from_str(&header_line)?;
        let header = match header_entry {
            TranscriptEntry::Header { version, supports_extended_length, keys, can } => {
                TranscriptHeader { version, supports_extended_length, keys, can }
            }
            _ => return Err(TranscriptError::InvalidHeader),
        };
        let mut entries = Vec::new();
        for line in lines {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            entries.push(serde_json::from_str::<TranscriptEntry>(&line)?);
        }
        Ok(Self { header, entries })
    }
}

pub struct ReplaySession {
    transcript: Transcript,
    cursor: usize,
}

impl ReplaySession {
    pub fn from_transcript(transcript: Transcript) -> Self {
        Self { transcript, cursor: 0 }
    }

    pub fn from_jsonl<P: AsRef<Path>>(path: P) -> Result<Self, TranscriptError> {
        Ok(Self::from_transcript(Transcript::from_jsonl(path)?))
    }

    pub fn supports_extended_length(&self) -> bool {
        self.transcript.supports_extended_length()
    }

    pub fn fixed_key_generator(&self) -> Result<Option<EcKeyPairGenerator>, TranscriptError> {
        self.transcript.fixed_key_generator()
    }

    pub fn transmit_bytes(&mut self, tx: &[u8]) -> Result<Vec<u8>, TranscriptError> {
        if self.cursor >= self.transcript.entries.len() {
            return Err(TranscriptError::ReplayExhausted);
        }
        let entry = &self.transcript.entries[self.cursor];
        self.cursor += 1;
        match entry {
            TranscriptEntry::Exchange { tx: expected_tx, rx, .. } => {
                let expected_tx =
                    hex::decode(expected_tx).map_err(|err| TranscriptError::InvalidTxHex(err.to_string()))?;
                if expected_tx != tx {
                    return Err(TranscriptError::ReplayMismatch);
                }
                let rx_bytes = hex::decode(rx).map_err(|err| TranscriptError::InvalidRxHex(err.to_string()))?;
                Ok(rx_bytes)
            }
            TranscriptEntry::Error { tx: expected_tx, error, .. } => {
                let expected_tx =
                    hex::decode(expected_tx).map_err(|err| TranscriptError::InvalidTxHex(err.to_string()))?;
                if expected_tx != tx {
                    return Err(TranscriptError::ReplayMismatch);
                }
                Err(TranscriptError::ReplayEntryError(error.clone()))
            }
            TranscriptEntry::Header { .. } => Err(TranscriptError::UnexpectedEntry("header")),
        }
    }
}

pub struct FixedKeyGenerator {
    keys: VecDeque<Vec<u8>>,
}

impl FixedKeyGenerator {
    pub fn new(keys: Vec<Vec<u8>>) -> Self {
        Self { keys: VecDeque::from(keys) }
    }

    pub fn generator(mut self) -> impl FnMut(EcCurve) -> Result<(EcPublicKey, EcPrivateKey), CryptoError> {
        move |curve| {
            let bytes = match self.keys.pop_front() {
                Some(bytes) => bytes,
                None => {
                    return Err(CryptoError::InvalidKeyMaterial { context: "fixed key generator ran out of keys" });
                }
            };
            let (public_key, private_key) = derive_keypair_from_scalar(curve.clone(), bytes)?;
            Ok((public_key, private_key))
        }
    }
}

fn derive_keypair_from_scalar(
    curve: EcCurve,
    private_bytes: Vec<u8>,
) -> Result<(EcPublicKey, EcPrivateKey), CryptoError> {
    let private_key = EcPrivateKey::from_bytes(curve.clone(), private_bytes);
    let scalar = BigInt::from_bytes_be(Sign::Plus, private_key.as_bytes());
    let public_point = curve.g().mul(&scalar)?;
    let public_key = public_point.to_ec_public_key()?;
    Ok((public_key, private_key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::error::CryptoError;

    #[test]
    fn transcript_roundtrip_jsonl() {
        let mut transcript = Transcript::new(true);
        transcript.set_keys(vec!["A1B2C3".to_string()]);
        transcript.set_can("123456");
        transcript.push_exchange(&[0x00], &[0x90, 0x00]);
        transcript.push_error(&[0x01], "failure");

        let jsonl = transcript.to_jsonl_string().unwrap();
        let parsed = Transcript::from_jsonl_str(&format!("\n{jsonl}\n")).unwrap();

        assert!(parsed.supports_extended_length());
        assert_eq!(parsed.keys().unwrap()[0], "A1B2C3");
        assert_eq!(parsed.can(), Some("123456"));
        assert_eq!(parsed.entries.len(), 2);
        match &parsed.entries[0] {
            TranscriptEntry::Exchange { tx, rx } => {
                assert_eq!(tx, "00");
                assert_eq!(rx, "9000");
            }
            _ => panic!("expected exchange entry"),
        }
        match &parsed.entries[1] {
            TranscriptEntry::Error { tx, error } => {
                assert_eq!(tx, "01");
                assert_eq!(error, "failure");
            }
            _ => panic!("expected error entry"),
        }
    }

    #[test]
    fn transcript_requires_header() {
        let input = r#"{"type":"exchange","tx":"00","rx":"9000"}"#;
        let err = Transcript::from_jsonl_str(input).unwrap_err();
        assert!(matches!(err, TranscriptError::InvalidHeader));
    }

    #[test]
    fn replay_session_matches_transcript_entries() {
        let mut transcript = Transcript::new(false);
        transcript.push_exchange(&[0xDE, 0xAD], &[0x90, 0x00]);
        let mut session = ReplaySession::from_transcript(transcript);
        let ok = session.transmit_bytes(&[0xDE, 0xAD]).unwrap();
        assert_eq!(ok, vec![0x90, 0x00]);
    }

    #[test]
    fn replay_session_reports_mismatch() {
        let mut transcript = Transcript::new(false);
        transcript.push_exchange(&[0x01], &[0x90, 0x00]);
        let mut session = ReplaySession::from_transcript(transcript);
        let err = session.transmit_bytes(&[0x02]).unwrap_err();
        assert!(matches!(err, TranscriptError::ReplayMismatch));
    }

    #[test]
    fn fixed_key_generator_consumes_keys() {
        let mut transcript = Transcript::new(true);
        transcript.set_keys(vec!["01".repeat(32)]);
        let mut generator = transcript.fixed_key_generator().unwrap().unwrap();

        let (public_key, private_key) = generator(EcCurve::BrainpoolP256r1).unwrap();
        assert_eq!(private_key.as_bytes().len(), 32);
        assert_eq!(public_key.curve(), &EcCurve::BrainpoolP256r1);

        match generator(EcCurve::BrainpoolP256r1) {
            Err(err) => assert!(matches!(err, CryptoError::InvalidKeyMaterial { .. })),
            Ok(_) => panic!("expected generator exhaustion"),
        }
    }
}
