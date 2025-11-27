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

use thiserror::Error;

/// Errors raised while composing healthcard commands prior to transmission.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CommandError {
    /// The supplied offset exceeds the allowed range for READ BINARY operations.
    #[error("offset {offset} outside allowed range 0..={max}")]
    OffsetOutOfRange { offset: i32, max: i32 },

    /// The supplied offset with SFI exceeds the allowed range.
    #[error("offset {offset} outside allowed SFI range 0..={max}")]
    SfiOffsetOutOfRange { offset: i32, max: i32 },

    /// Expected length was negative (other than the wildcard -1).
    #[error("expected length must be >= 0 or the wildcard -1, got {length}")]
    InvalidExpectedLength { length: i32 },
}
