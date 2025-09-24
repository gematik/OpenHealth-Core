#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
/// Strongly typed representation of lengths measured in bytes.
pub struct ByteUnit(u64);

#[cfg(feature = "uniffi")]
uniffi::custom_newtype!(ByteUnit, u64);

impl ByteUnit {
    /// Returns the number of bits in this byte unit.
    pub fn bits(self) -> u64 {
        self.0 * 8
    }

    /// Returns the number of bytes represented by this ByteUnit instance.
    pub fn bytes(self) -> u64 {
        self.0
    }
}

/// Extension methods to easily construct `ByteUnit` values from integers.
pub trait BytesExt {
    /// Interpret the integer as a count of bytes.
    fn bytes(self) -> ByteUnit;
    /// Interpret the integer as a count of bits, converting to bytes.
    /// Panics if not a multiple of 8.
    fn bits(self) -> ByteUnit;
}

const MULTIPLE_OF_EIGHT_MSG: &str = "Value must be multiple of 8";

macro_rules! impl_bytes_ext_unsigned {
    ($ty:ty) => {
        impl BytesExt for $ty {
            fn bytes(self) -> ByteUnit {
                ByteUnit(self as u64)
            }

            fn bits(self) -> ByteUnit {
                if self % 8 == 0 {
                    ByteUnit((self / 8) as u64)
                } else {
                    panic!("{}", MULTIPLE_OF_EIGHT_MSG)
                }
            }
        }
    };
}

macro_rules! impl_bytes_ext_signed {
    ($ty:ty) => {
        impl BytesExt for $ty {
            fn bytes(self) -> ByteUnit {
                assert!(self >= 0, "value must be non-negative");
                ByteUnit(self as u64)
            }

            fn bits(self) -> ByteUnit {
                assert!(self >= 0, "value must be non-negative");
                if self % 8 == 0 {
                    ByteUnit((self / 8) as u64)
                } else {
                    panic!("{}", MULTIPLE_OF_EIGHT_MSG)
                }
            }
        }
    };
}

impl_bytes_ext_unsigned!(usize);
impl_bytes_ext_unsigned!(u32);
impl_bytes_ext_signed!(i32);
