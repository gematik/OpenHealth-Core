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

use std::os::raw::{c_char, c_int};

use crate::ossl::api::{openssl_error, OsslResult};
use crypto_openssl_sys::{BIO_free, BIO_get_mem_data, BIO_new, BIO_new_mem_buf, BIO_s_mem, BIO};

/// BIO wrapper
pub struct Bio(*mut BIO);

impl Bio {
    /// Create a new memory BIO
    pub fn new_mem() -> OsslResult<Self> {
        let b = unsafe { BIO_new(BIO_s_mem()) };
        if b.is_null() {
            Err(openssl_error("Failed to create BIO"))
        } else {
            Ok(Bio(b))
        }
    }

    /// Create a BIO from a byte slice
    pub fn from_slice(data: &[u8]) -> OsslResult<Self> {
        let b = unsafe { BIO_new_mem_buf(data.as_ptr() as *const _, data.len() as c_int) };
        if b.is_null() {
            Err(openssl_error("Failed to create BIO from buffer"))
        } else {
            Ok(Bio(b))
        }
    }

    /// Read all bytes from BIO
    pub fn to_vec(&self) -> Vec<u8> {
        let mut ptr_data: *mut c_char = std::ptr::null_mut();
        let len = BIO_get_mem_data(self.0, &mut ptr_data) as isize;
        if len <= 0 || ptr_data.is_null() {
            return Vec::new();
        }
        // now cast to *const u8
        let slice = unsafe { std::slice::from_raw_parts(ptr_data as *const u8, len as usize) };
        slice.to_vec()
    }

    /// Get mutable pointer to the underlying BIO
    pub fn as_mut_ptr(&mut self) -> *mut BIO {
        self.0
    }
}
impl Drop for Bio {
    fn drop(&mut self) {
        unsafe { BIO_free(self.0) };
    }
}
