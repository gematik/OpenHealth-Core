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

use zeroize::Zeroize;

use crate::utils::byte_unit::{ByteUnit, BytesExt};

#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
/// Private (secret) key bytes that zeroize on drop.
pub struct PrivateKey(Vec<u8>);

impl PrivateKey {
    /// Construct a secret key from the provided bytes.
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into())
    }
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
impl PrivateKey {
    /// Return the length of the key in bytes.
    pub fn size(&self) -> ByteUnit {
        self.0.len().bytes()
    }

    /// Return a copy of the raw key bytes.
    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
impl PrivateKey {
    #[uniffi::constructor]
    /// Construct a secret key from bytes (UniFFI-friendly constructor).
    pub fn new_from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for PrivateKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for PrivateKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Abstraction for keys that expose their size in bytes.
pub trait KeySize {
    fn size(&self) -> ByteUnit;
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
/// Public key bytes.
pub struct PublicKey(Vec<u8>);

impl PublicKey {
    /// Construct a public key from the provided bytes.
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into())
    }
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
impl PublicKey {
    /// Return a copy of the raw public key bytes.
    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
impl KeySize for PublicKey {
    /// Return the public key length in bytes.
    fn size(&self) -> ByteUnit {
        self.0.len().bytes()
    }
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
impl PublicKey {
    #[uniffi::constructor]
    /// Construct a public key from bytes (UniFFI-friendly constructor).
    pub fn new_from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
