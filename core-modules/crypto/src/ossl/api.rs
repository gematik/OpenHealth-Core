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

use std::error;
use std::ffi::CStr;
use std::{fmt, ptr};

use crypto_openssl_sys::*;
use thiserror::Error;

#[cfg(test)]
use std::cell::Cell;
#[cfg(test)]
use std::thread::LocalKey;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum OsslErrorKind {
    #[error("{0}")]
    Message(String),
    #[error("OpenSSL check failed")]
    CheckFailed,
    #[error("OpenSSL requirement failed")]
    RequireFailed,

    #[error("Failed to create BIO")]
    BioCreateFailed,
    #[error("Failed to create BIO from buffer")]
    BioCreateFromBufferFailed,

    #[error("Failed to create cipher context")]
    CipherCtxCreateFailed,
    #[error("Failed to fetch cipher")]
    CipherFetchFailed,
    #[error("Failed to initialize cipher")]
    CipherInitFailed,
    #[error("Authentication tag cannot be empty")]
    CipherAuthTagEmpty,
    #[error("Failed to set IV length")]
    CipherSetIvLenFailed,
    #[error("Failed to set AAD")]
    CipherSetAadFailed,
    #[error("Failed to set authentication tag")]
    CipherSetAuthTagFailed,
    #[error("Failed to get authentication tag")]
    CipherGetAuthTagFailed,
    #[error("Encryption failed during update")]
    CipherUpdateEncryptFailed,
    #[error("Decryption failed during update")]
    CipherUpdateDecryptFailed,
    #[error("Encryption failed during finalization")]
    CipherFinalizeEncryptFailed,
    #[error("Decryption failed during finalization")]
    CipherFinalizeDecryptFailed,

    #[error("EVP_MAC_fetch failed")]
    MacFetchFailed,
    #[error("EVP_MAC_CTX_new failed")]
    MacCtxNewFailed,
    #[error("EVP_MAC_init failed")]
    MacInitFailed,
    #[error("EVP_MAC_update failed")]
    MacUpdateFailed,
    #[error("EVP_MAC_final failed to get output length")]
    MacFinalizeLenFailed,
    #[error("EVP_MAC_final failed to finalize")]
    MacFinalizeFailed,

    #[error("Invalid hash algorithm: {algorithm}")]
    DigestInvalidAlgorithm { algorithm: String },
    #[error("Failed to create EVP_MD_CTX")]
    DigestCtxCreateFailed,
    #[error("Failed to initialize digest")]
    DigestInitFailed,
    #[error("Failed to update digest")]
    DigestUpdateFailed,
    #[error("Failed to finalize XOF digest")]
    DigestFinalizeXofFailed,
    #[error("Failed to finalize digest")]
    DigestFinalizeFailed,

    #[error("Failed to load private key from DER")]
    KeyLoadPrivateDerFailed,
    #[error("Failed to load public key from DER")]
    KeyLoadPublicDerFailed,
    #[error("Failed to convert private key to DER")]
    KeyConvertPrivateToDerFailed,
    #[error("Failed to convert public key to DER")]
    KeyConvertPublicToDerFailed,

    #[error("Failed to get nid for curve {curve}")]
    EcNidLookupFailed { curve: String },
    #[error("Failed to create EC_GROUP")]
    EcGroupCreateFailed,
    #[error("Failed to create EC_POINT")]
    EcPointCreateFailed,
    #[error("Failed to create ec point from uncompressed public key")]
    EcPointFromBytesFailed,
    #[error("EC_POINT_add failed")]
    EcPointAddFailed,
    #[error("Failed to set affine coordinates")]
    EcPointSetAffineFailed,
    #[error("Failed to dup EC_GROUP")]
    EcGroupDupFailed,
    #[error("Failed to dup EC_POINT")]
    EcPointDupFailed,
    #[error("Failed to convert scalar to BIGNUM")]
    EcScalarToBignumFailed,
    #[error("Failed to multiply EC_POINT")]
    EcPointMulFailed,
    #[error("Failed to get public key size")]
    EcPublicKeySizeFailed,
    #[error("Error during ec point conversion")]
    EcPointConversionFailed,
    #[error("Failed to create EVP_PKEY_CTX")]
    EvpPkeyCtxCreateFailed,
    #[error("Failed to init keygen")]
    EcKeygenInitFailed,
    #[error("Invalid curve name: {curve}")]
    EcInvalidCurveName { curve: String },
    #[error("Failed to set EC curve")]
    EcSetCurveFailed,
    #[error("Key generation failed")]
    EcKeyGenerationFailed,
    #[error("Failed to create ECDH context")]
    EcdhCtxCreateFailed,
    #[error("Failed to init ECDH context")]
    EcdhInitFailed,
    #[error("Failed to set peer")]
    EcdhSetPeerFailed,
    #[error("Failed to compute secret")]
    EcdhComputeSecretFailed,

    #[error("Key initialization failed")]
    MlkemKeyInitFailed,
    #[error("Failed to create context from key")]
    MlkemCtxFromKeyFailed,
    #[error("Keygen context init failed")]
    MlkemKeygenCtxInitFailed,
    #[error("Keygen init failed")]
    MlkemKeygenInitFailed,
    #[error("Keygen failed")]
    MlkemKeygenFailed,
    #[error("Keygen returned null")]
    MlkemKeygenNull,
    #[error("Importing private key failed")]
    MlkemImportPrivateKeyFailed,
    #[error("Decapsulate init failed")]
    MlkemDecapsulateInitFailed,
    #[error("Decapsulate failed to get output length")]
    MlkemDecapsulateLenFailed,
    #[error("Decapsulate failed")]
    MlkemDecapsulateFailed,
    #[error("Extracting public key failed")]
    MlkemExtractPublicKeyFailed,
    #[error("Encapsulate init failed")]
    MlkemEncapsulateInitFailed,
    #[error("Encapsulate failed to get output length")]
    MlkemEncapsulateLenFailed,
    #[error("Encapsulate failed")]
    MlkemEncapsulateFailed,
    #[error("Failed to determine ML-KEM private key length")]
    MlkemPrivateKeyLenFailed,
    #[error("Failed to export ML-KEM private key")]
    MlkemPrivateKeyExportFailed,
}

/// OpenSSL error type
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OsslError {
    kind: OsslErrorKind,
    openssl_detail: Option<String>,
}

impl OsslError {
    pub fn new(kind: OsslErrorKind, openssl_detail: Option<String>) -> Self {
        Self { kind, openssl_detail }
    }

    pub fn kind(&self) -> &OsslErrorKind {
        &self.kind
    }

    pub fn openssl_detail(&self) -> Option<&str> {
        self.openssl_detail.as_deref()
    }
}

impl error::Error for OsslError {}

impl fmt::Display for OsslError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.openssl_detail() {
            Some(detail) => write!(f, "{}: {detail}", self.kind()),
            None => write!(f, "{}", self.kind()),
        }
    }
}

/// Retrieve and wrap the latest OpenSSL error
pub fn openssl_error(kind: OsslErrorKind) -> OsslError {
    // Fetch error code
    let err_code = unsafe { ERR_get_error() };
    // Get human-readable string
    let err_str = if err_code != 0 {
        Some(unsafe { CStr::from_ptr(ERR_error_string(err_code, ptr::null_mut())).to_string_lossy().into_owned() })
    } else {
        None
    };
    OsslError::new(kind, err_str)
}

/// Check return code equals 1, else error
#[macro_export]
macro_rules! ossl_check {
    ($ret:expr, $kind:expr) => {
        if $ret != 1 {
            return Err(openssl_error($kind));
        }
    };
}

#[macro_export]
macro_rules! ossl_require {
    ($cond:expr, $kind:expr) => {
        if !$cond {
            return Err(openssl_error($kind));
        }
    };
    ($cond:expr, $kind:expr, $cleanup:expr) => {
        if !$cond {
            $cleanup();
            return Err(openssl_error($kind));
        }
    };
}

/// Common result type for OpenSSL operations
pub type OsslResult<T> = Result<T, OsslError>;

#[cfg(test)]
pub(crate) fn with_thread_local_cell<T: Copy, R>(
    key: &'static LocalKey<Cell<T>>,
    temporary_value: T,
    f: impl FnOnce() -> R,
) -> R {
    struct CellRestore<T: Copy + 'static> {
        key: &'static LocalKey<Cell<T>>,
        previous_value: T,
    }

    impl<T: Copy + 'static> Drop for CellRestore<T> {
        fn drop(&mut self) {
            self.key.with(|cell| cell.set(self.previous_value));
        }
    }

    let previous_value = key.with(|cell| {
        let current = cell.get();
        cell.set(temporary_value);
        current
    });
    let _restore = CellRestore { key, previous_value };
    f()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ossl_error_kind_is_preserved() {
        let err = OsslError::new(OsslErrorKind::Message("message".to_string()), None);
        assert!(matches!(err.kind(), OsslErrorKind::Message(_)));
        assert_eq!(err.openssl_detail(), None);
    }

    #[test]
    fn openssl_error_includes_prefix() {
        let err = openssl_error(OsslErrorKind::Message("test".to_string()));
        assert!(matches!(err.kind(), OsslErrorKind::Message(_)));
    }

    #[test]
    fn ossl_check_macro_returns_error() {
        fn fail() -> OsslResult<()> {
            let ret = 0;
            ossl_check!(ret, OsslErrorKind::CheckFailed);
            Ok(())
        }

        let err = fail().err().expect("expected error");
        assert!(matches!(err.kind(), OsslErrorKind::CheckFailed));
    }
}
