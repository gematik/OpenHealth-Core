/*
 * Copyright 2025 gematik GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use thiserror::Error;

/// Error type for ASN.1 operations
#[derive(Error, Debug)]
pub enum Asn1Error {
    #[error("Encoding error: {0}")]
    EncodingError(String),

    #[error("Decoding error: {0}")]
    DecodingError(String),

    #[error("Invalid tag: {0}")]
    InvalidTag(String),

    #[error("Invalid length: {0}")]
    InvalidLength(String),

    #[error("Invalid format: {0}")]
    InvalidFormat(String),

    #[error("Unexpected error: {0}")]
    UnexpectedError(String),
}

/// Result type for ASN.1 operations
pub type Result<T> = std::result::Result<T, Asn1Error>;