// SPDX-FileCopyrightText: Copyright 2025 - 2026 gematik GmbH
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

use std::ops::Deref;
use zeroize::Zeroize;

#[derive(Zeroize, Clone, Debug, PartialEq, Eq)]
pub enum ZeroizingOption {
    None,
    Zeroes,
}

#[derive(Zeroize, Clone, Debug, PartialEq, Eq)]
pub struct VecOfU8 {
    vec: Vec<u8>,
    zeroizing_option: ZeroizingOption,
}

impl Drop for VecOfU8 {
    fn drop(&mut self) {
        if self.zeroizing_option == ZeroizingOption::Zeroes {
            self.zeroize();
        };
    }
}

impl VecOfU8 {
    pub fn new_nonzeroizing<V: Into<Vec<u8>>>(vec: V) -> Self {
        VecOfU8 { vec: vec.into(), zeroizing_option: ZeroizingOption::None }
    }

    pub fn new_zeroizing<V: Into<Vec<u8>>>(vec: V) -> Self {
        VecOfU8 { vec: vec.into(), zeroizing_option: ZeroizingOption::Zeroes }
    }

    pub fn new<V: Into<Vec<u8>>>(vec: V, opt: ZeroizingOption) -> Self {
        VecOfU8 { vec: vec.into(), zeroizing_option: opt }
    }

    pub fn push(&mut self, byte: u8) {
        self.vec.push(byte);
    }

    pub fn extend_from_slice(&mut self, bytes: &[u8]) {
        self.vec.extend_from_slice(bytes);
    }

    pub fn len(&self) -> usize {
        self.vec.len()
    }

    pub fn is_empty(&self) -> bool {
        self.vec.is_empty()
    }

    pub fn get_zeroizing_option(&self) -> ZeroizingOption {
        self.zeroizing_option.clone()
    }

    pub fn set_zeroizing(&mut self) {
        self.zeroizing_option = ZeroizingOption::Zeroes;
    }
}

impl AsRef<[u8]> for VecOfU8 {
    fn as_ref(&self) -> &[u8] {
        self.vec.as_ref()
    }
}

impl Deref for VecOfU8 {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        &self.vec
    }
}

#[cfg(test)]
mod tests {
    use crate::maybe_zeroizing_vec::{VecOfU8, ZeroizingOption};

    #[test]
    fn test_new_zeroizing() {
        let vec = vec![0xA0, 0x01, 0x02];
        let vec_of_u8 = VecOfU8::new_zeroizing(vec.clone());

        assert_eq!(vec_of_u8.as_ref(), vec.as_slice());
        assert_eq!(vec_of_u8.zeroizing_option, ZeroizingOption::Zeroes);
    }

    #[test]
    fn test_new_nonzeroizing() {
        let vec = vec![0xA0, 0x01, 0x02];
        let vec_of_u8 = VecOfU8::new_nonzeroizing(vec.clone());

        assert_eq!(vec_of_u8.as_ref(), vec.as_slice());
        assert_eq!(vec_of_u8.zeroizing_option, ZeroizingOption::None);
    }

    #[test]
    fn test_set_zeroizing() {
        let vec = vec![0xA0, 0x01, 0x02];
        let mut vec_of_u8 = VecOfU8::new_nonzeroizing(vec.clone());
        vec_of_u8.set_zeroizing();

        assert_eq!(vec_of_u8.zeroizing_option, ZeroizingOption::Zeroes);
    }

    #[test]
    fn test_len() {
        assert_eq!(VecOfU8::new_nonzeroizing(vec![0xA0, 0x01, 0x02]).len(), 3);
        assert_eq!(VecOfU8::new_nonzeroizing(vec![]).len(), 0);
    }

    #[test]
    fn test_is_empty() {
        assert!(!VecOfU8::new_nonzeroizing(vec![0xA0, 0x01, 0x02]).is_empty());
        assert!(VecOfU8::new_nonzeroizing(vec![]).is_empty());
    }
}
