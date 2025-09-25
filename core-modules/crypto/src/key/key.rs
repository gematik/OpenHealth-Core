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

use crate::utils::byte_unit::ByteUnit;

pub trait Key {
    fn data(&self) -> &[u8];
}

/// Represents a secret key in the cryptographic system.
#[derive(Clone)]
pub struct SecretKey {
    pub data: Vec<u8>,
    pub length: ByteUnit,
}

impl SecretKey {
    pub fn new(data: Vec<u8>) -> Self {
        let length = ByteUnit(data.len());
        Self { data, length }
    }
}

impl Key for SecretKey {
    fn data(&self) -> &[u8] {
        &self.data
    }
}

impl PartialEq for SecretKey {
    fn eq(&self, other: &Self) -> bool {
        self.data == other.data && self.length == other.length
    }
}

impl Eq for SecretKey {}

impl std::hash::Hash for SecretKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.data.hash(state);
        self.length.hash(state);
    }
}

impl std::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecretKey(data={:?})", self.data)
    }
}

impl std::fmt::Display for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecretKey(data={:?})", self.data)
    }
}