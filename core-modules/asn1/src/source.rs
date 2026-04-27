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

use std::sync::Arc;

/// Byte offsets for one parsed ASN.1 TLV inside its original source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Asn1Span {
    tag_start: usize,
    value_start: usize,
    value_end: usize,
    end: usize,
}

impl Asn1Span {
    pub fn new(tag_start: usize, value_start: usize, value_end: usize, end: usize) -> Self {
        Self { tag_start, value_start, value_end, end }
    }

    pub fn tag_start(&self) -> usize {
        self.tag_start
    }

    pub fn value_start(&self) -> usize {
        self.value_start
    }

    pub fn value_end(&self) -> usize {
        self.value_end
    }

    pub fn end(&self) -> usize {
        self.end
    }
}

/// A parsed value with the ASN.1 span it came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Spanned<T> {
    pub value: T,
    pub span: Asn1Span,
}

impl<T> Spanned<T> {
    pub fn new(value: T, span: Asn1Span) -> Self {
        Self { value, span }
    }

    pub fn into_value(self) -> T {
        self.value
    }
}

/// Shared original ASN.1 input bytes used to recover exact encoded TLVs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Asn1Source {
    bytes: Arc<[u8]>,
}

impl Asn1Source {
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self { bytes: Arc::<[u8]>::from(bytes.into()) }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn encoded(&self, span: Asn1Span) -> &[u8] {
        &self.bytes[span.tag_start..span.end]
    }

    pub fn value(&self, span: Asn1Span) -> &[u8] {
        &self.bytes[span.value_start..span.value_end]
    }
}
