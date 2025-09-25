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

use std::error::Error;
use std::ffi::CStr;
use std::{fmt, ptr};
use crypto_openssl_sys::*;

/// OpenSSL error type
#[derive(Debug)]
pub struct OsslError {
    msg: String,
}

impl fmt::Display for OsslError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.msg)
    }
}

impl Error for OsslError {}

/// Retrieve and wrap the latest OpenSSL error
pub fn throw_openssl_error(msg: &str) -> OsslError {
    // Fetch error code
    let err_code = unsafe { ERR_get_error() };
    // Get human-readable string
    let err_str = if err_code != 0 {
        unsafe {
            CStr::from_ptr(ERR_error_string(err_code, ptr::null_mut()))
                .to_string_lossy()
                .into_owned()
        }
    } else {
        String::new()
    };
    OsslError { msg: format!("{}: {}", msg, err_str) }
}

/// Check return code equals 1, else error
#[macro_export]
macro_rules! ossl_check {
    ($ret:expr, $msg:expr) => {
        if $ret != 1 {
            return Err(throw_openssl_error($msg));
        }
    };
}
