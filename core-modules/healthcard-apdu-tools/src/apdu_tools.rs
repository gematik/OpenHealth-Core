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

use healthcard::command::apdu::{CardCommandApdu, CardResponseApdu};
use healthcard::exchange::channel::CardChannel;
use healthcard::exchange::ExchangeError;
use healthcard_apdu_base::{EcKeyPairGenerator, ReplaySession, Transcript, TranscriptError};
use std::path::Path;

#[cfg(feature = "pcsc")]
use std::ffi::CString;

pub struct RecordingChannel<C: CardChannel> {
    inner: C,
    transcript: Transcript,
}

impl<C: CardChannel> RecordingChannel<C> {
    pub fn new(inner: C) -> Self {
        let transcript = Transcript::new(inner.supports_extended_length());
        Self { inner, transcript }
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
                self.transcript.push_exchange(&tx, &response.to_bytes());
                Ok(response)
            }
            Err(err) => {
                self.transcript.push_error(&tx, format!("{err:?}"));
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
                self.transcript.push_exchange(&tx, &response.to_bytes());
                Ok(response)
            }
            Err(err) => {
                self.transcript.push_error(&tx, format!("{err:?}"));
                Err(err)
            }
        }
    }
}

pub struct ReplayChannel {
    session: ReplaySession,
}

impl ReplayChannel {
    pub fn from_transcript(transcript: Transcript) -> Self {
        Self { session: ReplaySession::from_transcript(transcript) }
    }

    pub fn fixed_key_generator(&self) -> Result<Option<EcKeyPairGenerator>, TranscriptError> {
        self.session.fixed_key_generator()
    }

    pub fn from_jsonl<P: AsRef<Path>>(path: P) -> Result<Self, TranscriptError> {
        Ok(Self { session: ReplaySession::from_jsonl(path)? })
    }
}

impl CardChannel for ReplayChannel {
    type Error = ExchangeError;

    fn supports_extended_length(&self) -> bool {
        self.session.supports_extended_length()
    }

    fn transmit(&mut self, command: &CardCommandApdu) -> Result<CardResponseApdu, Self::Error> {
        let tx = command.to_bytes();
        let rx = self
            .session
            .transmit_bytes(&tx)
            .map_err(|err| ExchangeError::Transport { code: 0, message: err.to_string() })?;
        CardResponseApdu::new(&rx).map_err(ExchangeError::from)
    }
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
            .map_err(|_| ExchangeError::Transport { code: 0, message: "pcsc reader name contains NUL".to_string() })?;
        let card = ctx
            .connect(&reader_cstr, pcsc::ShareMode::Shared, pcsc::Protocols::ANY)
            .map_err(|err| ExchangeError::Transport { code: 0, message: format!("pcsc connect failed: {err}") })?;
        Ok(Self { card, supports_extended_length, recv_buffer: vec![0u8; 65538] })
    }

    pub fn connect_first_reader(supports_extended_length: bool) -> Result<Self, ExchangeError> {
        let ctx = pcsc::Context::establish(pcsc::Scope::User).map_err(|err| ExchangeError::Transport {
            code: 0,
            message: format!("pcsc context establish failed: {err}"),
        })?;
        let readers = ctx
            .list_readers_owned()
            .map_err(|err| ExchangeError::Transport { code: 0, message: format!("pcsc list readers failed: {err}") })?;
        let reader = readers
            .first()
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
    use healthcard::command::apdu::{CardCommandApdu, CardResponseApdu};
    use healthcard::exchange::channel::CardChannel;

    struct MockSession {
        responses: Vec<CardResponseApdu>,
        supports_extended_length: bool,
    }

    impl MockSession {
        fn new(responses: Vec<Vec<u8>>) -> Self {
            let responses =
                responses.into_iter().map(|raw| CardResponseApdu::new(&raw).expect("valid response APDU")).collect();
            Self { responses, supports_extended_length: false }
        }
    }

    impl CardChannel for MockSession {
        type Error = ExchangeError;

        fn supports_extended_length(&self) -> bool {
            self.supports_extended_length
        }

        fn transmit(&mut self, _command: &CardCommandApdu) -> Result<CardResponseApdu, Self::Error> {
            if self.responses.is_empty() {
                Err(ExchangeError::Transport { code: 0, message: "mock session ran out of responses".to_string() })
            } else {
                Ok(self.responses.remove(0))
            }
        }
    }

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
        let curve = crypto::ec::ec_key::EcCurve::BrainpoolP256r1;
        let keys = vec![vec![0x01; 32], vec![0x02; 32]];
        let mut generator = healthcard_apdu_base::FixedKeyGenerator::new(keys).generator();
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
        let curve = crypto::ec::ec_key::EcCurve::BrainpoolP256r1;
        let (_pub1, priv1) = generator(curve.clone()).unwrap();
        assert_eq!(priv1.as_bytes(), key1.as_slice());
        let (_pub2, priv2) = generator(curve).unwrap();
        assert_eq!(priv2.as_bytes(), key2.as_slice());
    }

    #[cfg(feature = "pcsc")]
    mod pcsc_tests {
        use super::*;
        use healthcard::command::health_card_command::HealthCardCommand;
        use healthcard::command::SelectCommand;
        use healthcard::exchange::channel::CardChannelExt;

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
