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

/// OpenSSL error type
#[derive(Debug)]
pub struct OsslError(pub String);

impl error::Error for OsslError {}

impl fmt::Display for OsslError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Retrieve and wrap the latest OpenSSL error
pub fn openssl_error(msg: &str) -> OsslError {
    // Fetch error code
    let err_code = unsafe { ERR_get_error() };
    // Get human-readable string
    let err_str = if err_code != 0 {
        Some(unsafe { CStr::from_ptr(ERR_error_string(err_code, ptr::null_mut())).to_string_lossy().into_owned() })
    } else {
        None
    };
    OsslError(format!("{msg}{}", err_str.map(|s| format!(": {s}")).unwrap_or_default()))
}

/// Check return code equals 1, else error
#[macro_export]
macro_rules! ossl_check {
    ($ret:expr, $msg:expr) => {
        if $ret != 1 {
            return Err(openssl_error($msg));
        }
    };
}

#[macro_export]
macro_rules! ossl_require {
    ($cond:expr, $msg:expr) => {
        if !$cond {
            return Err(openssl_error($msg));
        }
    };
    ($cond:expr, $msg:expr, $cleanup:expr) => {
        if !$cond {
            $cleanup();
            return Err(openssl_error($msg));
        }
    };
}

/// Common result type for OpenSSL operations
pub type OsslResult<T> = Result<T, OsslError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ossl_error_display() {
        let err = OsslError("message".to_string());
        assert_eq!(err.to_string(), "message");
    }

    #[test]
    fn openssl_error_includes_prefix() {
        let err = openssl_error("test");
        assert!(err.to_string().starts_with("test"));
    }

    #[test]
    fn ossl_check_macro_returns_error() {
        fn fail() -> OsslResult<()> {
            let ret = 0;
            ossl_check!(ret, "check failed");
            Ok(())
        }

        let err = fail().expect_err("expected error");
        assert!(err.to_string().starts_with("check failed"));
    }
}
