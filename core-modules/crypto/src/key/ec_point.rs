/*
 * Copyright 2025 gematik GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use num_bigint::BigInt;
use std::fmt;
use std::ops::{Add, Mul};
use thiserror::Error;

/// Feature flag to mark experimental crypto APIs
#[allow(dead_code)]
pub const EXPERIMENTAL_CRYPTO_API: &str = "experimental_crypto_api";

/// Represents an elliptic curve type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EcCurve {
    BrainpoolP256r1,
    BrainpoolP384r1,
    BrainpoolP512r1,
}

impl EcCurve {
    /// Returns the order (p) of the underlying field for this curve
    pub fn p(&self) -> BigInt {
        match self {
            EcCurve::BrainpoolP256r1 => BigInt::parse_bytes(
                b"A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377",
                16,
            ).unwrap(),
            EcCurve::BrainpoolP384r1 => BigInt::parse_bytes(
                b"8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B412B1DA197FB71123ACD3A729901D1A71874700133107EC53",
                16,
            ).unwrap(),
            EcCurve::BrainpoolP512r1 => BigInt::parse_bytes(
                b"AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA703308717D4D9B009BC66842AECDA12AE6A380E62881FF2F2D82C68528AA6056583A48F3",
                16,
            ).unwrap(),
        }
    }

    /// Creates a new EC point on this curve with the given coordinates
    pub fn point(&self, x: Option<BigInt>, y: Option<BigInt>) -> Result<EcPoint, EcPointError> {
        EcPoint::new(*self, x, y)
    }

    /// Returns the coordinate size in bytes for this curve
    pub fn coordinate_size(&self) -> usize {
        match self {
            EcCurve::BrainpoolP256r1 => 32,
            EcCurve::BrainpoolP384r1 => 48,
            EcCurve::BrainpoolP512r1 => 64,
        }
    }
}

/// Error types for EC point operations
#[derive(Error, Debug)]
pub enum EcPointError {
    #[error("X and Y must be both Some or None")]
    InvalidCoordinates,

    #[error("Cannot encode infinite EC point to uncompressed representation")]
    InfinitePointEncoding,

    #[error("Points must be on the same curve")]
    CurveMismatch,

    #[error("Invalid point encoding: {0}")]
    InvalidEncoding(String),
}

/// Represents a point on an elliptic curve.
///
/// An EC point is defined by its coordinates (x, y) and the elliptic curve it belongs to.
/// It can also represent the point at infinity, which is denoted by having both x and y coordinates as None.
///
/// The x and y coordinates are not verified to lie on the specified curve.
#[derive(Clone, PartialEq, Eq)]
pub struct EcPoint {
    /// The elliptic curve this point belongs to
    pub curve: EcCurve,

    /// The x-coordinate of the point, or None if it is at infinity
    pub x: Option<BigInt>,

    /// The y-coordinate of the point, or None if it is at infinity
    pub y: Option<BigInt>,
}

impl EcPoint {
    /// Creates a new EC point on the specified curve.
    ///
    /// # Arguments
    /// * `curve` - The elliptic curve this point belongs to
    /// * `x` - The x-coordinate of the point, or None if it is at infinity
    /// * `y` - The y-coordinate of the point, or None if it is at infinity
    ///
    /// # Returns
    /// A new EC point instance
    ///
    /// # Errors
    /// Returns an error if x and y are not both None or both Some
    pub fn new(curve: EcCurve, x: Option<BigInt>, y: Option<BigInt>) -> Result<Self, EcPointError> {
        match (&x, &y) {
            (None, None) | (Some(_), Some(_)) => Ok(Self { curve, x, y }),
            _ => Err(EcPointError::InvalidCoordinates),
        }
    }

    /// Returns the uncompressed representation of the EC point.
    ///
    /// The uncompressed representation consists of a leading byte (0x04) followed by
    /// the X coordinate and the Y coordinate, both as big-endian integers.
    ///
    /// # Returns
    /// A byte array with the uncompressed representation
    ///
    /// # Errors
    /// Returns an error if the EC point is at infinity
    pub fn to_uncompressed(&self) -> Result<Vec<u8>, EcPointError> {
        if self.is_infinity() {
            return Err(EcPointError::InfinitePointEncoding);
        }

        let coordinate_size = self.curve.coordinate_size();
        let total_size = 1 + 2 * coordinate_size;
        let mut result = vec![0u8; total_size];

        // Set the prefix byte
        result[0] = 0x04;

        // Convert x and y to byte arrays
        let x_bytes = self.x.as_ref().unwrap().to_bytes_be().1;
        let y_bytes = self.y.as_ref().unwrap().to_bytes_be().1;

        // Copy x into the result array with appropriate padding
        let x_offset = coordinate_size - x_bytes.len().min(coordinate_size);
        for (i, byte) in x_bytes.iter().rev().enumerate().take(coordinate_size) {
            result[1 + coordinate_size - 1 - i] = *byte;
        }

        // Copy y into the result array with appropriate padding
        let y_offset = coordinate_size - y_bytes.len().min(coordinate_size);
        for (i, byte) in y_bytes.iter().rev().enumerate().take(coordinate_size) {
            result[1 + 2 * coordinate_size - 1 - i] = *byte;
        }

        Ok(result)
    }

    /// Returns true if this represents an infinite point
    pub fn is_infinity(&self) -> bool {
        self.x.is_none() && self.y.is_none()
    }

    /// Adds this EC point to another EC point
    pub fn add(&self, other: &EcPoint) -> Result<EcPoint, EcPointError> {
        if self.curve != other.curve {
            return Err(EcPointError::CurveMismatch);
        }

        // Use the elliptic curve library for actual implementation
        // This is a placeholder for the actual implementation
        self.native_add(other)
    }

    /// Multiplies this EC point by a scalar value
    pub fn multiply(&self, k: &BigInt) -> Result<EcPoint, EcPointError> {
        // Use the elliptic curve library for actual implementation
        // This is a placeholder for the actual implementation
        self.native_multiply(k)
    }

    /// Negates this EC point
    pub fn negate(&self) -> Result<EcPoint, EcPointError> {
        if self.is_infinity() {
            return Ok(self.clone());
        }

        let p = self.curve.p();
        let y = &p - self.y.as_ref().unwrap() % &p;

        EcPoint::new(self.curve, self.x.clone(), Some(y))
    }

    /// Internal function for native implementation of point addition
    fn native_add(&self, other: &EcPoint) -> Result<EcPoint, EcPointError> {
        // In a real implementation, this would use a cryptographic library like 'p256', 'k256', etc.
        // For now, we'll use a stub implementation

        // Handle special cases
        if self.is_infinity() {
            return Ok(other.clone());
        }
        if other.is_infinity() {
            return Ok(self.clone());
        }

        // For demonstration purposes, we'll implement a very simplified addition
        // In reality, you would use a proper EC library implementation

        // Placeholder code - NOT a real EC point addition!
        let x_sum = (self.x.as_ref().unwrap() + other.x.as_ref().unwrap()) % &self.curve.p();
        let y_sum = (self.y.as_ref().unwrap() + other.y.as_ref().unwrap()) % &self.curve.p();

        EcPoint::new(self.curve, Some(x_sum), Some(y_sum))
    }

    /// Internal function for native implementation of scalar multiplication
    fn native_multiply(&self, k: &BigInt) -> Result<EcPoint, EcPointError> {
        // In a real implementation, this would use a cryptographic library like 'p256', 'k256', etc.
        // For now, we'll use a stub implementation

        // Handle special cases
        if self.is_infinity() || k == &BigInt::from(0) {
            // Return point at infinity for k = 0 or if this is already at infinity
            return EcPoint::new(self.curve, None, None);
        }

        // For demonstration purposes, we'll implement a very simplified multiplication
        // In reality, you would use a proper EC library implementation

        // Placeholder code - NOT a real EC point multiplication!
        let x_mult = (self.x.as_ref().unwrap() * k) % &self.curve.p();
        let y_mult = (self.y.as_ref().unwrap() * k) % &self.curve.p();

        EcPoint::new(self.curve, Some(x_mult), Some(y_mult))
    }
}

impl fmt::Debug for EcPoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_infinity() {
            write!(f, "EcPoint({:?}, infinity)", self.curve)
        } else {
            write!(f, "EcPoint({:?}, x={}, y={})",
                   self.curve,
                   self.x.as_ref().unwrap().to_str_radix(16),
                   self.y.as_ref().unwrap().to_str_radix(16))
        }
    }
}

impl Add for &EcPoint {
    type Output = Result<EcPoint, EcPointError>;

    fn add(self, other: &EcPoint) -> Self::Output {
        self.add(other)
    }
}

impl Mul<&BigInt> for &EcPoint {
    type Output = Result<EcPoint, EcPointError>;

    fn mul(self, k: &BigInt) -> Self::Output {
        self.multiply(k)
    }
}

/// Represents an EC public key.
pub struct EcPublicKey {
    /// The elliptic curve this key belongs to
    pub curve: EcCurve,

    /// The uncompressed encoding of the public key
    pub encoded: Vec<u8>,
}

impl EcPublicKey {
    /// Creates a new EC public key from the given curve and encoding
    pub fn new(curve: EcCurve, encoded: Vec<u8>) -> Self {
        Self { curve, encoded }
    }

    /// Extracts the EC point from this public key
    pub fn to_point(&self) -> Result<EcPoint, EcPointError> {
        let encoded = &self.encoded;

        // Basic validation
        if encoded.is_empty() || encoded[0] != 0x04 {
            return Err(EcPointError::InvalidEncoding("Not in uncompressed format".to_string()));
        }

        let coordinate_size = self.curve.coordinate_size();
        let expected_length = 1 + 2 * coordinate_size;

        if encoded.len() != expected_length {
            return Err(EcPointError::InvalidEncoding(format!(
                "Invalid encoding length: expected {}, got {}",
                expected_length,
                encoded.len()
            )));
        }

        // Extract x and y coordinates
        let x_bytes = &encoded[1..(1 + coordinate_size)];
        let y_bytes = &encoded[(1 + coordinate_size)..];

        let x = BigInt::from_bytes_be(num_bigint::Sign::Plus, x_bytes);
        let y = BigInt::from_bytes_be(num_bigint::Sign::Plus, y_bytes);

        EcPoint::new(self.curve, Some(x), Some(y))
    }
}

/// Extension trait to convert an EC point to an EC public key
pub trait ToEcPublicKey {
    fn to_ec_public_key(&self) -> Result<EcPublicKey, EcPointError>;
}

impl ToEcPublicKey for EcPoint {
    fn to_ec_public_key(&self) -> Result<EcPublicKey, EcPointError> {
        let encoded = self.to_uncompressed()?;
        Ok(EcPublicKey::new(self.curve, encoded))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ec_point_creation() {
        // Valid point creation
        let x = BigInt::from(123);
        let y = BigInt::from(456);
        let result = EcPoint::new(EcCurve::BrainpoolP256r1, Some(x.clone()), Some(y.clone()));
        assert!(result.is_ok());

        let point = result.unwrap();
        assert_eq!(point.x.unwrap(), x);
        assert_eq!(point.y.unwrap(), y);
        assert_eq!(point.curve, EcCurve::BrainpoolP256r1);

        // Point at infinity
        let result = EcPoint::new(EcCurve::BrainpoolP256r1, None, None);
        assert!(result.is_ok());

        let point = result.unwrap();
        assert!(point.is_infinity());

        // Invalid point creation (only x is None)
        let result = EcPoint::new(EcCurve::BrainpoolP256r1, None, Some(y));
        assert!(result.is_err());

        // Invalid point creation (only y is None)
        let result = EcPoint::new(EcCurve::BrainpoolP256r1, Some(x), None);
        assert!(result.is_err());
    }

    #[test]
    fn test_uncompressed_encoding() {
        // Create a point
        let x = BigInt::from(123);
        let y = BigInt::from(456);
        let point = EcPoint::new(EcCurve::BrainpoolP256r1, Some(x), Some(y)).unwrap();

        // Get uncompressed encoding
        let result = point.to_uncompressed();
        assert!(result.is_ok());

        let encoded = result.unwrap();
        assert_eq!(encoded[0], 0x04); // Check prefix
        assert_eq!(encoded.len(), 1 + 2 * 32); // Check length (1 + 2*32 for BrainpoolP256r1)

        // Infinite point cannot be encoded
        let infinite = EcPoint::new(EcCurve::BrainpoolP256r1, None, None).unwrap();
        let result = infinite.to_uncompressed();
        assert!(result.is_err());
    }

    #[test]
    fn test_point_negation() {
        // Create a point
        let x = BigInt::from(123);
        let y = BigInt::from(456);
        let point = EcPoint::new(EcCurve::BrainpoolP256r1, Some(x.clone()), Some(y.clone())).unwrap();

        // Negate the point
        let negated = point.negate().unwrap();

        // Check coordinates
        assert_eq!(negated.x.unwrap(), x);
        let p = EcCurve::BrainpoolP256r1.p();
        let expected_y = &p - &y % &p;
        assert_eq!(negated.y.unwrap(), expected_y);

        // Negation of point at infinity
        let infinite = EcPoint::new(EcCurve::BrainpoolP256r1, None, None).unwrap();
        let negated = infinite.negate().unwrap();
        assert!(negated.is_infinity());
    }

    #[test]
    fn test_point_to_public_key() {
        // Create a point
        let x = BigInt::from(123);
        let y = BigInt::from(456);
        let point = EcPoint::new(EcCurve::BrainpoolP256r1, Some(x), Some(y)).unwrap();

        // Convert to a public key
        let result = point.to_ec_public_key();
        assert!(result.is_ok());

        let public_key = result.unwrap();
        assert_eq!(public_key.curve, EcCurve::BrainpoolP256r1);
        assert_eq!(public_key.encoded[0], 0x04);
        assert_eq!(public_key.encoded.len(), 1 + 2 * 32);

        // Convert back to point
        let recovered = public_key.to_point().unwrap();
        assert_eq!(recovered.x, point.x);
        assert_eq!(recovered.y, point.y);
        assert_eq!(recovered.curve, point.curve);
    }
}