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

use crate::exchange::ExchangeError;
use crate::ffi::trusted_channel::TrustedChannelError;
use thiserror::Error;

/// Error type returned by the foreign card channel implementation.
#[derive(Debug, Clone, Error)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Error))]
pub enum CardChannelError {
    #[error("transport error: {0}")]
    Transport(#[from] TrustedChannelError),
}

#[uniffi::export(with_foreign)]
pub trait CardChannel: Send + Sync {
    fn supports_extended_length(&self) -> bool;

    fn transmit(&self, command: Vec<u8>) -> Result<Vec<u8>, CardChannelError>;
}

impl From<CardChannelError> for ExchangeError {
    fn from(err: CardChannelError) -> Self {
        match err {
            CardChannelError::Transport(inner) => match inner {
                TrustedChannelError::Transport { code, reason } => ExchangeError::Transport { code, message: reason },
                other => ExchangeError::Transport { code: 0, message: other.to_string() },
            },
        }
    }
}
