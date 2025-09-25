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

//! Represents a unit of byte measurement.

/// Represents a unit of byte measurement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ByteUnit(pub usize);

impl ByteUnit {
    /// Returns the number of bits in this byte unit.
    pub fn bits(self) -> usize {
        self.0 * 8
    }

    /// Returns the number of bytes represented by this ByteUnit instance.
    pub fn bytes(self) -> usize {
        self.0
    }
}

/// Returns a `ByteUnit` instance representing the specified number of bytes.
pub trait BytesExt {
    fn bytes(self) -> ByteUnit;
    fn bits(self) -> ByteUnit;
}

impl BytesExt for usize {
    fn bytes(self) -> ByteUnit {
        ByteUnit(self)
    }

    fn bits(self) -> ByteUnit {
        if self % 8 == 0 {
            ByteUnit(self / 8)
        } else {
            panic!("Value must be multiple of 8")
        }
    }
}

impl BytesExt for u32 {
    fn bytes(self) -> ByteUnit {
        ByteUnit(self as usize)
    }

    fn bits(self) -> ByteUnit {
        if self % 8 == 0 {
            ByteUnit((self / 8) as usize)
        } else {
            panic!("Value must be multiple of 8")
        }
    }
}

impl BytesExt for i32 {
    fn bytes(self) -> ByteUnit {
        ByteUnit(self as usize)
    }

    fn bits(self) -> ByteUnit {
        if self % 8 == 0 {
            ByteUnit((self / 8) as usize)
        } else {
            panic!("Value must be multiple of 8")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    trait ValueExt {
        fn value(&self) -> usize;
    }
    impl ValueExt for ByteUnit {
        fn value(&self) -> usize {
            self.0
        }
    }

    #[test]
    fn create_byte_unit_from_bytes() {
        let byte_unit = 8usize.bytes();
        assert_eq!(8, byte_unit.value());
    }

    #[test]
    fn create_byte_unit_from_valid_bits() {
        let byte_unit = 16usize.bits();
        assert_eq!(2, byte_unit.value());
    }

    #[test]
    #[should_panic(expected = "Value must be multiple of 8")]
    fn create_byte_unit_from_invalid_bits_throws_error() {
        let _ = 3usize.bits();
    }

    #[test]
    fn convert_byte_unit_to_bits() {
        let byte_unit = ByteUnit(4);
        assert_eq!(32, byte_unit.bits());
    }

    #[test]
    fn convert_byte_unit_to_bytes() {
        let byte_unit = ByteUnit(4);
        assert_eq!(4, byte_unit.bytes());
    }

    #[test]
    fn zero_is_valid_for_both_bits_and_bytes() {
        assert_eq!(0, 0usize.bytes().value());
        assert_eq!(0, 0usize.bits().value());
    }

    #[test]
    fn large_numbers_are_handled_correctly() {
        let large_bytes = 1024usize.bytes();
        assert_eq!(1024, large_bytes.value());
        assert_eq!(8192, large_bytes.bits());

        let large_bits = 8192usize.bits();
        assert_eq!(1024, large_bits.value());
        assert_eq!(8192, large_bits.bits());
    }
}
