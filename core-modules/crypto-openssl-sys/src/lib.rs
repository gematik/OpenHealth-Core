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

#![allow(
    clippy::cast_lossless,
    clippy::cast_possible_truncation,
    clippy::default_trait_access,
    clippy::must_use_candidate,
    clippy::not_unsafe_ptr_arg_deref,
    clippy::ptr_as_ptr,
    clippy::pub_underscore_fields,
    clippy::semicolon_if_nothing_returned,
    clippy::too_many_lines,
    clippy::unreadable_literal,
    clippy::used_underscore_binding,
    clippy::useless_transmute,
    dead_code,
    improper_ctypes,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused_imports
)]

use std::os::raw::{c_char, c_long, c_void};

include!("ossl.rs");

#[allow(non_snake_case, clippy::not_unsafe_ptr_arg_deref)]
pub fn BIO_get_mem_data(b: *mut BIO, pp: *mut *mut c_char) -> c_long {
    unsafe { BIO_ctrl(b, BIO_CTRL_INFO, 0, pp.cast::<c_void>()) }
}
