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

use asn1::maybe_zeroizing_vec::VecOfU8 as Asn1VecOfU8;
use std::sync::Arc;

/// a wrapped Vec<u8> that might be zeroized (depending on it's configuration)
#[derive(uniffi::Object, Debug, PartialEq, Eq)]
pub struct VecOfU8 {
    inner: Asn1VecOfU8,
}

impl VecOfU8 {
    pub(crate) fn from_core(inner: Asn1VecOfU8) -> Arc<Self> {
        Arc::new(Self { inner })
    }

    #[allow(dead_code)]
    pub(crate) fn from_nonzeroizing_bytes(bytes: Vec<u8>) -> Arc<Self> {
        Arc::new(Self { inner: Asn1VecOfU8::new_nonzeroizing(bytes) })
    }
}

#[uniffi::export]
impl VecOfU8 {
    pub fn clone_as_nonzeroizing_vec(&self) -> Vec<u8> {
        self.inner.as_ref().to_vec()
    }
}
