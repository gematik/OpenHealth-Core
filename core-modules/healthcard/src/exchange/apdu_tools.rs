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

use crate::command::apdu::{CardCommandApdu, CardResponseApdu};
use crate::exchange::channel::CardChannel;
use crate::exchange::ExchangeError;
use crypto::ec::ec_key::{EcCurve, EcPrivateKey, EcPublicKey};
use crypto::error::CryptoError;
use num_bigint::{BigInt, Sign};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use thiserror::Error;

#[cfg(feature = "pcsc")]
use std::ffi::CString;

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
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct TranscriptHeader {
    version: u32,
    supports_extended_length: bool,
    label: Option<String>,
    keys: Option<Vec<String>>,
    can: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum TranscriptEntry {
    Header {
        version: u32,
        supports_extended_length: bool,
        label: Option<String>,
        keys: Option<Vec<String>>,
        can: Option<String>,
    },
    Exchange {
        tx: String,
        rx: String,
        label: Option<String>,
    },
    Error {
        tx: String,
        error: String,
        label: Option<String>,
    },
}

#[derive(Clone, Debug)]
pub struct Transcript {
    header: TranscriptHeader,
    entries: Vec<TranscriptEntry>,
}

impl Transcript {
    pub fn new(supports_extended_length: bool) -> Self {
        Self {
            header: TranscriptHeader { version: 1, supports_extended_length, label: None, keys: None, can: None },
            entries: Vec::new(),
        }
    }

    pub fn supports_extended_length(&self) -> bool {
        self.header.supports_extended_length
    }

    pub fn set_label(&mut self, label: impl Into<String>) {
        self.header.label = Some(label.into());
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

    pub fn push_exchange(&mut self, tx: &[u8], rx: &[u8], label: Option<String>) {
        self.entries.push(TranscriptEntry::Exchange { tx: hex::encode_upper(tx), rx: hex::encode_upper(rx), label });
    }

    pub fn push_error(&mut self, tx: &[u8], error: impl Into<String>, label: Option<String>) {
        self.entries.push(TranscriptEntry::Error { tx: hex::encode_upper(tx), error: error.into(), label });
    }

    pub fn to_jsonl_string(&self) -> Result<String, TranscriptError> {
        let mut out = String::new();
        let header = TranscriptEntry::Header {
            version: self.header.version,
            supports_extended_length: self.header.supports_extended_length,
            label: self.header.label.clone(),
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
        let header_line = lines.next().ok_or(TranscriptError::InvalidHeader)?;
        let header_entry: TranscriptEntry = serde_json::from_str(header_line)?;
        let header = match header_entry {
            TranscriptEntry::Header { version, supports_extended_length, label, keys, can } => {
                TranscriptHeader { version, supports_extended_length, label, keys, can }
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
        let header_line = lines.next().ok_or(TranscriptError::InvalidHeader)??;
        let header_entry: TranscriptEntry = serde_json::from_str(&header_line)?;
        let header = match header_entry {
            TranscriptEntry::Header { version, supports_extended_length, label, keys, can } => {
                TranscriptHeader { version, supports_extended_length, label, keys, can }
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

pub struct RecordingChannel<C: CardChannel> {
    inner: C,
    transcript: Transcript,
}

impl<C: CardChannel> RecordingChannel<C> {
    pub fn new(inner: C) -> Self {
        let transcript = Transcript::new(inner.supports_extended_length());
        Self { inner, transcript }
    }

    pub fn set_label(&mut self, label: impl Into<String>) {
        self.transcript.set_label(label);
    }

    pub fn set_keys(&mut self, keys: Vec<String>) {
        self.transcript.set_keys(keys);
    }

    pub fn set_can(&mut self, can: impl Into<String>) {
        self.transcript.set_can(can);
    }

    pub fn transcript(&self) -> &Transcript {
        &self.transcript
    }

    pub fn into_transcript(self) -> Transcript {
        self.transcript
    }
}

impl<C> CardChannel for RecordingChannel<C>
where
    C: CardChannel,
    C::Error: std::fmt::Debug,
{
    type Error = C::Error;

    fn supports_extended_length(&self) -> bool {
        self.inner.supports_extended_length()
    }

    fn transmit(&mut self, command: &CardCommandApdu) -> Result<CardResponseApdu, Self::Error> {
        let tx = command.to_bytes();
        match self.inner.transmit(command) {
            Ok(response) => {
                self.transcript.push_exchange(&tx, &response.to_bytes(), None);
                Ok(response)
            }
            Err(err) => {
                self.transcript.push_error(&tx, format!("{err:?}"), None);
                Err(err)
            }
        }
    }
}

impl<C> CardChannel for &mut RecordingChannel<C>
where
    C: CardChannel,
    C::Error: std::fmt::Debug,
{
    type Error = C::Error;

    fn supports_extended_length(&self) -> bool {
        self.inner.supports_extended_length()
    }

    fn transmit(&mut self, command: &CardCommandApdu) -> Result<CardResponseApdu, Self::Error> {
        let tx = command.to_bytes();
        match self.inner.transmit(command) {
            Ok(response) => {
                self.transcript.push_exchange(&tx, &response.to_bytes(), None);
                Ok(response)
            }
            Err(err) => {
                self.transcript.push_error(&tx, format!("{err:?}"), None);
                Err(err)
            }
        }
    }
}

pub struct ReplayChannel {
    transcript: Transcript,
    cursor: usize,
}

impl ReplayChannel {
    pub fn from_transcript(transcript: Transcript) -> Self {
        Self { transcript, cursor: 0 }
    }

    pub fn fixed_key_generator(&self) -> Result<Option<EcKeyPairGenerator>, TranscriptError> {
        self.transcript.fixed_key_generator()
    }

    pub fn from_jsonl<P: AsRef<Path>>(path: P) -> Result<Self, TranscriptError> {
        Ok(Self::from_transcript(Transcript::from_jsonl(path)?))
    }

    fn next_entry(&mut self) -> Result<TranscriptEntry, TranscriptError> {
        if self.cursor >= self.transcript.entries.len() {
            return Err(TranscriptError::ReplayExhausted);
        }
        let entry = self.transcript.entries[self.cursor].clone();
        self.cursor += 1;
        Ok(entry)
    }
}

impl CardChannel for ReplayChannel {
    type Error = ExchangeError;

    fn supports_extended_length(&self) -> bool {
        self.transcript.supports_extended_length()
    }

    fn transmit(&mut self, command: &CardCommandApdu) -> Result<CardResponseApdu, Self::Error> {
        let entry = self.next_entry().map_err(|err| ExchangeError::Transport { code: 0, message: err.to_string() })?;
        match entry {
            TranscriptEntry::Exchange { tx, rx, .. } => {
                let expected_tx = hex::decode(tx)
                    .map_err(|err| ExchangeError::Transport { code: 0, message: format!("invalid tx hex: {err}") })?;
                let actual_tx = command.to_bytes();
                if expected_tx != actual_tx {
                    return Err(ExchangeError::Transport {
                        code: 0,
                        message: "replay mismatch: outgoing APDU does not match transcript".to_string(),
                    });
                }
                let rx_bytes = hex::decode(rx)
                    .map_err(|err| ExchangeError::Transport { code: 0, message: format!("invalid rx hex: {err}") })?;
                Ok(CardResponseApdu::new(&rx_bytes)?)
            }
            TranscriptEntry::Error { tx, error, .. } => {
                let expected_tx = hex::decode(tx)
                    .map_err(|err| ExchangeError::Transport { code: 0, message: format!("invalid tx hex: {err}") })?;
                let actual_tx = command.to_bytes();
                if expected_tx != actual_tx {
                    return Err(ExchangeError::Transport {
                        code: 0,
                        message: "replay mismatch: outgoing APDU does not match transcript".to_string(),
                    });
                }
                Err(ExchangeError::Transport { code: 0, message: format!("replayed error: {error}") })
            }
            TranscriptEntry::Header { .. } => Err(ExchangeError::Transport {
                code: 0,
                message: TranscriptError::UnexpectedEntry("header").to_string(),
            }),
        }
    }
}

pub struct FixedKeyGenerator {
    keys: Vec<Vec<u8>>,
}

impl FixedKeyGenerator {
    pub fn new(keys: Vec<Vec<u8>>) -> Self {
        Self { keys }
    }

    pub fn generator(mut self) -> impl FnMut(EcCurve) -> Result<(EcPublicKey, EcPrivateKey), CryptoError> {
        move |curve| {
            if self.keys.is_empty() {
                return Err(CryptoError::InvalidKeyMaterial { context: "fixed key generator ran out of keys" });
            }
            let bytes = self.keys.remove(0);
            let key_hex = hex::encode_upper(&bytes);
            let (public_key, private_key) = derive_keypair_from_scalar(curve.clone(), bytes)?;
            eprintln!("FixedKeyGenerator used key for {curve:?}: {key_hex}");
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

#[cfg(feature = "pcsc")]
pub struct PcscChannel {
    card: pcsc::Card,
    supports_extended_length: bool,
    recv_buffer: Vec<u8>,
}

#[cfg(feature = "pcsc")]
impl PcscChannel {
    pub fn connect(reader: &str, supports_extended_length: bool) -> Result<Self, ExchangeError> {
        let ctx = pcsc::Context::establish(pcsc::Scope::User).map_err(|err| ExchangeError::Transport {
            code: 0,
            message: format!("pcsc context establish failed: {err}"),
        })?;
        let reader_cstr = CString::new(reader)
            .map_err(|err| ExchangeError::Transport { code: 0, message: format!("invalid reader name: {err}") })?;
        let card = ctx
            .connect(&reader_cstr, pcsc::ShareMode::Shared, pcsc::Protocols::ANY)
            .map_err(|err| ExchangeError::Transport { code: 0, message: format!("pcsc connect failed: {err}") })?;
        Ok(Self { card, supports_extended_length, recv_buffer: vec![0u8; 65538] })
    }

    pub fn connect_first(supports_extended_length: bool) -> Result<Self, ExchangeError> {
        let ctx = pcsc::Context::establish(pcsc::Scope::User).map_err(|err| ExchangeError::Transport {
            code: 0,
            message: format!("pcsc context establish failed: {err}"),
        })?;
        let mut readers = ctx
            .list_readers_owned()
            .map_err(|err| ExchangeError::Transport { code: 0, message: format!("pcsc list readers failed: {err}") })?;
        let reader = readers
            .pop()
            .ok_or_else(|| ExchangeError::Transport { code: 0, message: "no pcsc readers found".to_string() })?;
        let card = ctx
            .connect(reader.as_c_str(), pcsc::ShareMode::Shared, pcsc::Protocols::ANY)
            .map_err(|err| ExchangeError::Transport { code: 0, message: format!("pcsc connect failed: {err}") })?;
        Ok(Self { card, supports_extended_length, recv_buffer: vec![0u8; 65538] })
    }
}

#[cfg(feature = "pcsc")]
impl CardChannel for PcscChannel {
    type Error = ExchangeError;

    fn supports_extended_length(&self) -> bool {
        self.supports_extended_length
    }

    fn transmit(&mut self, command: &CardCommandApdu) -> Result<CardResponseApdu, Self::Error> {
        let tx = command.to_bytes();
        let response = self
            .card
            .transmit(&tx, &mut self.recv_buffer)
            .map_err(|err| ExchangeError::Transport { code: 0, message: format!("pcsc transmit failed: {err}") })?;
        CardResponseApdu::new(response).map_err(ExchangeError::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::apdu::CardCommandApdu;
    use crate::exchange::test_utils::MockSession;

    #[test]
    fn record_and_replay_roundtrip() {
        let mut recorder = RecordingChannel::new(MockSession::new(vec![vec![0x90, 0x00]]));
        let command = CardCommandApdu::header_only(0x00, 0xA4, 0x04, 0x00).unwrap();
        let _ = recorder.transmit(&command).unwrap();
        let transcript = recorder.into_transcript();

        let jsonl = transcript.to_jsonl_string().unwrap();
        let replay = Transcript::from_jsonl_str(&jsonl).unwrap();
        let mut channel = ReplayChannel::from_transcript(replay);
        let response = channel.transmit(&command).unwrap();
        assert_eq!(response.to_bytes(), vec![0x90, 0x00]);
    }

    #[test]
    fn fixed_key_generator_returns_keys() {
        let curve = EcCurve::BrainpoolP256r1;
        let keys = vec![vec![0x01; 32], vec![0x02; 32]];
        let mut generator = FixedKeyGenerator::new(keys).generator();
        let (pub1, priv1) = generator(curve.clone()).unwrap();
        assert_eq!(priv1.as_bytes().len(), 32);
        assert_eq!(pub1.as_bytes().len(), 65);
        let (_pub2, priv2) = generator(curve).unwrap();
        assert_eq!(priv2.as_bytes().len(), 32);
    }

    #[test]
    fn transcript_keys_roundtrip_and_generator() {
        let mut transcript = Transcript::new(true);
        let key1 = vec![0xAA; 32];
        let key2 = vec![0xBB; 32];
        let keys_hex = vec![hex::encode_upper(&key1), hex::encode_upper(&key2)];
        transcript.set_keys(keys_hex.clone());

        let jsonl = transcript.to_jsonl_string().unwrap();
        let parsed = Transcript::from_jsonl_str(&jsonl).unwrap();
        assert_eq!(parsed.keys().unwrap(), keys_hex.as_slice());

        let mut generator = parsed.fixed_key_generator().unwrap().unwrap();
        let curve = EcCurve::BrainpoolP256r1;
        let (_pub1, priv1) = generator(curve.clone()).unwrap();
        assert_eq!(priv1.as_bytes(), key1.as_slice());
        let (_pub2, priv2) = generator(curve).unwrap();
        assert_eq!(priv2.as_bytes(), key2.as_slice());
    }

    #[cfg(feature = "pcsc")]
    mod pcsc_tests {
        use super::*;
        use crate::command::health_card_command::HealthCardCommand;
        use crate::exchange::channel::CardChannelExt;

        #[test]
        fn pcsc_record_and_replay_select_mf() {
            let reader = match std::env::var("HEALTHCARD_PCSC_READER") {
                Ok(reader) => reader,
                Err(_) => return,
            };

            let channel = PcscChannel::connect(&reader, true).expect("pcsc connect");
            let mut recorder = RecordingChannel::new(channel);
            let response = recorder.execute_command(&HealthCardCommand::select(false, false)).expect("select MF");
            let response_bytes = response.apdu.to_bytes();

            let transcript = recorder.into_transcript();
            let mut replay = ReplayChannel::from_transcript(transcript);
            let replay_response =
                replay.execute_command(&HealthCardCommand::select(false, false)).expect("replay select MF");
            assert_eq!(replay_response.apdu.to_bytes(), response_bytes);
        }

        #[test]
        fn list_pcsc_readers() {
            let ctx = match pcsc::Context::establish(pcsc::Scope::User) {
                Ok(ctx) => ctx,
                Err(err) => {
                    println!("pcsc context establish failed: {err}");
                    return;
                }
            };
            let readers = match ctx.list_readers_owned() {
                Ok(readers) => readers,
                Err(err) => {
                    println!("pcsc list readers failed: {err}");
                    return;
                }
            };
            if readers.is_empty() {
                println!("no pcsc readers found");
                return;
            }
            println!("pcsc readers:");
            for reader in readers {
                println!("  {}", reader.to_string_lossy());
            }
        }
    }
}
