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

use crate::utils::byte_unit::{ByteUnit, BytesExt};
use core::marker::PhantomData;
use zeroize::Zeroizing;

pub struct SecretKey {
    bytes: Zeroizing<Vec<u8>>,
}

impl SecretKey {
    pub fn new_secret(bytes: impl Into<Vec<u8>>) -> Self {
        SecretKey { bytes: Zeroizing::new(bytes.into()) }
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    pub fn size(&self) -> ByteUnit {
        self.bytes.len().bytes()
    }
}

impl AsRef<[u8]> for SecretKey {
    fn as_ref(&self) -> &[u8] {
        self.bytes.as_ref()
    }
}

impl From<Vec<u8>> for SecretKey {
    fn from(value: Vec<u8>) -> Self {
        SecretKey::new_secret(value)
    }
}

impl std::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretKey").field("size", &self.size()).finish_non_exhaustive()
    }
}

impl PartialEq<Self> for SecretKey {
    fn eq(&self, other: &Self) -> bool {
        todo!()
    }
}
