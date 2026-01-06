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

pub mod certificate;
pub mod channel;
pub mod error;
pub mod ids;
pub mod pace_info;
pub mod pin;
pub mod random;
pub mod read_vsd;
pub mod sign_challenge;
#[cfg(test)]
pub(crate) mod test_utils;
#[cfg(any(feature = "apdu-tools", test))]
pub mod apdu_tools;
pub mod secure_channel;

pub use certificate::retrieve_certificate;
pub use error::ExchangeError;
pub use pin::{unlock_egk, verify_pin, HealthCardVerifyPinResult, UnlockMethod};
pub use random::get_random;
pub use read_vsd::read_vsd;
pub use sign_challenge::sign_challenge;
pub use secure_channel::{
    establish_secure_channel, establish_secure_channel_with, CardAccessNumber, SecureChannel,
};
