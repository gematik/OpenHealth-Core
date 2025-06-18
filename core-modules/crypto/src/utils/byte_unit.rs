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