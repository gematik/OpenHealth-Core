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

#![cfg(test)]

use crate::command::apdu::{CardCommandApdu, CardResponseApdu};
use crate::exchange::session::CardChannel;
use crate::exchange::ExchangeError;

/// Test helper for simulating a card session with predetermined responses.
pub(crate) struct MockSession {
    responses: Vec<CardResponseApdu>,
    pub(crate) recorded: Vec<Vec<u8>>,
    supports_extended_length: bool,
}

impl MockSession {
    /// Create a mock session that does not support extended length APDUs.
    pub(crate) fn new(responses: Vec<Vec<u8>>) -> Self {
        Self::with_extended_support(responses, false)
    }

    /// Create a mock session with an explicit extended-length capability flag.
    pub(crate) fn with_extended_support(responses: Vec<Vec<u8>>, supports_extended_length: bool) -> Self {
        let responses =
            responses.into_iter().map(|raw| CardResponseApdu::new(&raw).expect("valid response APDU")).collect();
        Self { responses, recorded: Vec::new(), supports_extended_length }
    }
}

impl CardChannel for MockSession {
    type Error = ExchangeError;

    fn supports_extended_length(&self) -> bool {
        self.supports_extended_length
    }

    fn transmit(&mut self, command: &CardCommandApdu) -> Result<CardResponseApdu, Self::Error> {
        self.recorded.push(command.apdu());
        if self.responses.is_empty() {
            Err(ExchangeError::Transport { code: 0, message: "mock session ran out of responses".to_string() })
        } else {
            Ok(self.responses.remove(0))
        }
    }
}
