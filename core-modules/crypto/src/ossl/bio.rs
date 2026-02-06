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

use crate::ossl::api::{openssl_error, OsslErrorKind, OsslResult};
use crypto_openssl_sys::{BIO_free, BIO_get_mem_data, BIO_new, BIO_new_mem_buf, BIO_s_mem, BIO};

#[cfg(test)]
use std::cell::Cell;

#[cfg(test)]
thread_local! {
    static FORCE_BIO_NEW_NULL: Cell<bool> = const { Cell::new(false) };
    static FORCE_BIO_NEW_MEM_BUF_NULL: Cell<bool> = const { Cell::new(false) };
    static FORCE_BIO_GET_MEM_DATA_ZERO: Cell<bool> = const { Cell::new(false) };
    static FORCE_BIO_GET_MEM_DATA_NULL_PTR: Cell<bool> = const { Cell::new(false) };
}

#[inline]
fn bio_new_mem() -> *mut BIO {
    #[cfg(test)]
    {
        if FORCE_BIO_NEW_NULL.with(|flag| flag.get()) {
            return std::ptr::null_mut();
        }
    }
    unsafe { BIO_new(BIO_s_mem()) }
}

#[inline]
fn bio_new_mem_buf(data: *const u8, len: c_int) -> *mut BIO {
    #[cfg(test)]
    {
        if FORCE_BIO_NEW_MEM_BUF_NULL.with(|flag| flag.get()) {
            return std::ptr::null_mut();
        }
    }
    unsafe { BIO_new_mem_buf(data as *const _, len) }
}

#[inline]
fn bio_get_mem_data(bio: *mut BIO, data: *mut *mut c_char) -> isize {
    #[cfg(test)]
    {
        if FORCE_BIO_GET_MEM_DATA_ZERO.with(|flag| flag.get()) {
            unsafe { *data = std::ptr::null_mut() };
            return 0;
        }
        if FORCE_BIO_GET_MEM_DATA_NULL_PTR.with(|flag| flag.get()) {
            unsafe { *data = std::ptr::null_mut() };
            return 1;
        }
    }
    BIO_get_mem_data(bio, data) as isize
}

/// BIO wrapper
pub struct Bio(*mut BIO);

impl Bio {
    /// Create a new memory BIO
    pub fn new_mem() -> OsslResult<Self> {
        let b = bio_new_mem();
        if b.is_null() {
            Err(openssl_error(OsslErrorKind::BioCreateFailed))
        } else {
            Ok(Bio(b))
        }
    }

    /// Create a BIO from a byte slice
    pub fn from_slice(data: &[u8]) -> OsslResult<Self> {
        let b = bio_new_mem_buf(data.as_ptr(), data.len() as c_int);
        if b.is_null() {
            Err(openssl_error(OsslErrorKind::BioCreateFromBufferFailed))
        } else {
            Ok(Bio(b))
        }
    }

    /// Read all bytes from BIO
    pub fn to_vec(&self) -> Vec<u8> {
        let mut ptr_data: *mut c_char = std::ptr::null_mut();
        let len = bio_get_mem_data(self.0, &mut ptr_data);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ossl::api::with_thread_local_cell;
    use crate::ossl::api::OsslErrorKind;

    #[test]
    fn new_mem_to_vec_empty() {
        let bio = Bio::new_mem().unwrap();
        assert!(bio.to_vec().is_empty());
    }

    #[test]
    fn from_slice_to_vec_roundtrip() {
        let data = b"hello";
        let bio = Bio::from_slice(data).unwrap();
        assert_eq!(bio.to_vec(), data);
    }

    #[test]
    fn new_mem_fails_when_null() {
        let err = with_thread_local_cell(&FORCE_BIO_NEW_NULL, true, Bio::new_mem).err().expect("expected error");
        assert_eq!(err.kind(), &OsslErrorKind::BioCreateFailed);
    }

    #[test]
    fn from_slice_fails_when_null() {
        let err = with_thread_local_cell(&FORCE_BIO_NEW_MEM_BUF_NULL, true, || Bio::from_slice(b"hello"))
            .err()
            .expect("expected error");
        assert_eq!(err.kind(), &OsslErrorKind::BioCreateFromBufferFailed);
    }

    #[test]
    fn to_vec_returns_empty_when_mem_data_missing() {
        let bio = Bio::new_mem().unwrap();
        let data = with_thread_local_cell(&FORCE_BIO_GET_MEM_DATA_ZERO, true, || bio.to_vec());
        assert!(data.is_empty());
    }

    #[test]
    fn to_vec_returns_empty_when_ptr_null() {
        let bio = Bio::new_mem().unwrap();
        let data = with_thread_local_cell(&FORCE_BIO_GET_MEM_DATA_NULL_PTR, true, || bio.to_vec());
        assert!(data.is_empty());
    }
}
