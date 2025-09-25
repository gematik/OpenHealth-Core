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

use std::sync::Mutex;

use crate::cipher::aes::Cipher;
use crate::{cipher, ossl};

pub use crate::error::CryptoResult;

// Safety: OpenSSL EVP cipher contexts are not thread-safe for concurrent use.
// In this crate, all access goes through a Mutex (no concurrent use), and the
// object may be moved across threads by UniFFI.
unsafe impl Send for ossl::cipher::AesCipher {}

#[derive(uniffi::Object)]
/// Thread-safe wrapper around the high-level AES cipher for UniFFI consumers.
pub struct AesCipher {
    inner: Mutex<cipher::aes::AesCipher>,
}

impl From<cipher::aes::AesCipher> for AesCipher {
    fn from(inner: cipher::aes::AesCipher) -> Self {
        Self {
            inner: Mutex::new(inner),
        }
    }
}

#[uniffi::export]
impl AesCipher {
    /// Process more input and return produced output bytes.
    fn update(&self, input: &[u8]) -> CryptoResult<Vec<u8>> {
        let mut cipher = self.inner.lock().unwrap();
        let mut output = Vec::new();
        cipher.update(input, &mut output)?;
        Ok(output)
    }

    /// Finalize the operation and return any remaining output bytes.
    fn finalize(&self) -> CryptoResult<Vec<u8>> {
        let mut cipher = self.inner.lock().unwrap();
        let mut output = Vec::new();
        cipher.finalize(&mut output)?;
        Ok(output)
    }
}
