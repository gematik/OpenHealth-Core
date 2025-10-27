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

use crate::ec::ec_key::{EcCurve, EcPublicKey};
use crate::error::{CryptoError, CryptoResult};
use num_bigint::BigInt;

/// Elliptic curve point representation.
///
/// Supports:
/// - Finite points with affine coordinates (x, y) on a specific curve
/// - The point at infinity on a specific curve
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EcPoint {
    /// A finite point with affine coordinates on the given curve.
    Finite { curve: EcCurve, x: BigInt, y: BigInt },
    /// The point at infinity on the given curve.
    Infinity { curve: EcCurve },
}

impl EcPoint {
    /// Constructs a finite point on the given curve with the provided affine coordinates.
    ///
    /// Note: This function does not validate that (x, y) lies on the curve.
    pub fn finite(curve: EcCurve, x: BigInt, y: BigInt) -> Self {
        EcPoint::Finite { curve, x, y }
    }

    /// Constructs the point at infinity on the given curve.
    pub fn infinity(curve: EcCurve) -> Self {
        EcPoint::Infinity { curve }
    }

    /// Returns references to (curve, x, y) if this is a finite point; otherwise None.
    pub fn as_finite(&self) -> Option<(&EcCurve, &BigInt, &BigInt)> {
        if let EcPoint::Finite { curve, x, y } = self {
            Some((curve, x, y))
        } else {
            None
        }
    }

    /// Returns a reference to the associated curve.
    pub fn curve(&self) -> &EcCurve {
        match self {
            EcPoint::Finite { curve, .. } | EcPoint::Infinity { curve, .. } => curve,
        }
    }

    /// Returns the x coordinate if this is a finite point; otherwise None.
    pub fn x_coord(&self) -> Option<&BigInt> {
        match self {
            EcPoint::Finite { x, .. } => Some(x),
            EcPoint::Infinity { .. } => None,
        }
    }

    /// Returns the y coordinate if this is a finite point; otherwise None.
    pub fn y_coord(&self) -> Option<&BigInt> {
        match self {
            EcPoint::Finite { y, .. } => Some(y),
            EcPoint::Infinity { .. } => None,
        }
    }

    /// Returns true if this point is the point at infinity.
    pub fn is_infinity(&self) -> bool {
        matches!(self, EcPoint::Infinity { .. })
    }

    /// Returns the uncompressed SEC1 encoding of this point.
    ///
    /// Format:
    /// - 0x04 || X || Y
    /// - X and Y are big-endian, left-padded to the curve coordinate size.
    ///
    /// Errors:
    /// - InvalidEcPoint if called on the point at infinity.
    /// - InvalidEcPoint if any coordinate exceeds the curve's coordinate size.
    pub fn uncompressed(&self) -> CryptoResult<Vec<u8>> {
        match self {
            EcPoint::Infinity { .. } => Err(CryptoError::InvalidEcPoint("cannot encode point at infinity".to_string())),
            EcPoint::Finite { x, y, .. } => {
                let coordinate_size = match self.curve() {
                    EcCurve::BrainpoolP256r1 => 32,
                    EcCurve::BrainpoolP384r1 => 48,
                    EcCurve::BrainpoolP512r1 => 64,
                };
                let size = 1 + 2 * coordinate_size;

                let mut out = vec![0u8; size];

                let x_bytes = x.to_signed_bytes_be();
                let y_bytes = y.to_signed_bytes_be();

                // Left-pad with zeros to fixed coordinate size
                let x_offset = 1 + coordinate_size - x_bytes.len();
                let y_offset = 1 + coordinate_size + coordinate_size - y_bytes.len();

                out[y_offset..(y_offset + y_bytes.len())].copy_from_slice(&y_bytes);
                out[x_offset..(x_offset + x_bytes.len())].copy_from_slice(&x_bytes);
                out[0] = 0x04;

                Ok(out)
            }
        }
    }

    /// Adds two EC points on the same curve.
    ///
    /// Returns:
    /// - The sum as a new EcPoint.
    ///
    /// Errors:
    /// - InvalidEcPoint if the points belong to different curves.
    /// - Propagates lower-level errors from the underlying EC implementation.
    pub fn add(&self, other: &EcPoint) -> CryptoResult<EcPoint> {
        self.native_plus(other)
    }

    /// Multiplies this point by a scalar k (signed big-endian).
    ///
    /// Returns:
    /// - k * self as a new EcPoint.
    ///
    /// Special cases:
    /// - If self is infinity, returns infinity.
    ///
    /// Errors:
    /// - Propagates lower-level errors from the underlying EC implementation.
    pub fn mul(&self, k: &BigInt) -> CryptoResult<EcPoint> {
        self.native_times(k)
    }

    /// Returns the negation of this point (x, -y mod p). Infinity negates to itself.
    pub fn negate(&self) -> EcPoint {
        match self {
            EcPoint::Infinity { .. } => self.clone(),
            EcPoint::Finite { curve, x, y } => {
                let p = curve.p();
                let y = ((&p - y) % &p + &p) % &p;
                curve.point(x.clone(), y)
            }
        }
    }

    fn native_times(&self, k: &BigInt) -> CryptoResult<EcPoint> {
        match self {
            EcPoint::Infinity { .. } => Ok(self.clone()),
            EcPoint::Finite { curve, .. } => {
                let p = crate::ossl::ec::EcPoint::from_public(curve.name(), &self.uncompressed()?)?;
                let pk = p.mul(&k.to_signed_bytes_be())?;
                Ok(EcPublicKey::from_uncompressed(curve.clone(), pk.to_bytes()?)?.to_ec_point())
            }
        }
    }

    fn native_plus(&self, other: &EcPoint) -> CryptoResult<EcPoint> {
        match (self, other) {
            (EcPoint::Infinity { .. }, _) => Ok(other.clone()),
            (_, EcPoint::Infinity { .. }) => Ok(self.clone()),
            (EcPoint::Finite { curve: ca, .. }, EcPoint::Finite { curve: cb, .. }) => {
                if ca != cb {
                    return Err(CryptoError::InvalidEcPoint("points are on different curves".to_string()));
                }
                let pa = crate::ossl::ec::EcPoint::from_public(ca.name(), &self.uncompressed()?)?;
                let pb = crate::ossl::ec::EcPoint::from_public(cb.name(), &other.uncompressed()?)?;
                let pr = pa.add(&pb)?;
                Ok(EcPublicKey::from_uncompressed(ca.clone(), pr.to_bytes()?)?.to_ec_point())
            }
        }
    }

    /// Converts this point to an EcPublicKey using uncompressed SEC1 encoding.
    ///
    /// Errors:
    /// - Propagates errors from uncompressed() and key construction.
    pub fn to_ec_public_key(&self) -> CryptoResult<EcPublicKey> {
        EcPublicKey::from_uncompressed(self.curve().clone(), &self.uncompressed()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::BigInt;
    use num_traits::One;

    fn hex_bigint(s: &str) -> BigInt {
        BigInt::parse_bytes(s.as_bytes(), 16).unwrap()
    }

    #[test]
    fn test_point_at_infinity() {
        let curve = EcCurve::BrainpoolP256r1;
        let point = EcPoint::infinity(curve.clone());
        assert!(point.is_infinity());
    }

    #[test]
    fn test_regular_point() {
        let curve = EcCurve::BrainpoolP256r1;
        let x = hex_bigint("78028496B5ECAAB3C8B6C12E45DB1E02C9E4D26B4113BC4F015F60C5CCC0D206");
        let y = hex_bigint("A2AE1762A3831C1D20F03F8D1E3C0C39AFE6F09B4D44BBE80CD100987B05F92B");
        let point = EcPoint::finite(curve.clone(), x.clone(), y.clone());
        assert!(!point.is_infinity());
        assert_eq!(Some(&x), point.x_coord());
        assert_eq!(Some(&y), point.y_coord());
    }

    #[test]
    fn test_point_negation() {
        let curve = EcCurve::BrainpoolP256r1;
        let x = hex_bigint("78028496B5ECAAB3C8B6C12E45DB1E02C9E4D26B4113BC4F015F60C5CCC0D206");
        let y = hex_bigint("A2AE1762A3831C1D20F03F8D1E3C0C39AFE6F09B4D44BBE80CD100987B05F92B");
        let point = EcPoint::finite(curve.clone(), x.clone(), y.clone());
        let negated = point.negate();
        if let EcPoint::Finite { x: nx, y: ny, .. } = negated {
            assert_eq!(x, nx);
            let expected_y = ((curve.p() - &y) % curve.p() + curve.p()) % curve.p();
            assert_eq!(expected_y, ny);
        } else {
            panic!("negated point should be finite");
        }
    }

    #[test]
    fn test_uncompressed_encoding() {
        let curve = EcCurve::BrainpoolP256r1;
        let x = hex_bigint("78028496B5ECAAB3C8B6C12E45DB1E02C9E4D26B4113BC4F015F60C5CCC0D206");
        let y = hex_bigint("A2AE1762A3831C1D20F03F8D1E3C0C39AFE6F09B4D44BBE80CD100987B05F92B");
        let point = EcPoint::finite(curve, x, y);
        let uncompressed = point.uncompressed().unwrap();
        assert_eq!(65, uncompressed.len());
        assert_eq!(0x04, uncompressed[0]);
    }

    #[test]
    #[should_panic]
    fn test_uncompressed_encoding_of_infinity() {
        let curve = EcCurve::BrainpoolP256r1;
        let point = EcPoint::infinity(curve);
        point.uncompressed().unwrap();
    }

    #[test]
    fn test_curve_coordinate_sizes() {
        let x = BigInt::one();
        let y = BigInt::one();
        let p256_point = EcPoint::finite(EcCurve::BrainpoolP256r1, x.clone(), y.clone());
        assert_eq!(65, p256_point.uncompressed().unwrap().len());

        let p384_point = EcPoint::finite(EcCurve::BrainpoolP384r1, x.clone(), y.clone());
        assert_eq!(97, p384_point.uncompressed().unwrap().len());

        let p512_point = EcPoint::finite(EcCurve::BrainpoolP512r1, x, y);
        assert_eq!(129, p512_point.uncompressed().unwrap().len());
    }

    #[test]
    fn test_to_ec_public_key() {
        let curve = EcCurve::BrainpoolP256r1;
        let x = hex_bigint("78028496B5ECAAB3C8B6C12E45DB1E02C9E4D26B4113BC4F015F60C5CCC0D206");
        let y = hex_bigint("A2AE1762A3831C1D20F03F8D1E3C0C39AFE6F09B4D44BBE80CD100987B05F92B");
        let point = EcPoint::finite(curve.clone(), x, y);
        let public_key = point.to_ec_public_key().unwrap();
        assert_eq!(curve, public_key.curve);
        assert_eq!(point.uncompressed().unwrap(), public_key.data);
    }
}
