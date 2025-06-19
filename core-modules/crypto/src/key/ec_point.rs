use num_bigint::BigInt;
use crate::key::ec_key::{EcCurve, EcPublicKey};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcPoint {
    pub curve: EcCurve,
    pub x: Option<BigInt>,
    pub y: Option<BigInt>,
}

impl EcPoint {
    pub fn new(curve: EcCurve, x: Option<BigInt>, y: Option<BigInt>) -> Self {
        assert!(
            (x.is_none() && y.is_none()) || (x.is_some() && y.is_some()),
            "X and Y must be both None or both Some"
        );
        EcPoint { curve, x, y }
    }

    /// Returns the uncompressed representation of the EC point.
    /// Length: 65, 97, or 129 depending on the curve.
    pub fn uncompressed(&self) -> Vec<u8> {
        assert!(
            !self.is_infinity(),
            "Can't encode infinite ec point to its uncompressed representation"
        );
        let (size, coordinate_size) = match self.curve {
            EcCurve::BrainpoolP256r1 => (65, 32),
            EcCurve::BrainpoolP384r1 => (97, 48),
            EcCurve::BrainpoolP512r1 => (129, 64),
        };
        let mut out = vec![0u8; size];
        out[0] = 0x04;
        let x_bytes = self.x.as_ref().unwrap().to_signed_bytes_be();
        let y_bytes = self.y.as_ref().unwrap().to_signed_bytes_be();

        let x_offset = 1 + coordinate_size - x_bytes.len();
        let y_offset = 1 + 2 * coordinate_size - y_bytes.len();

        out[x_offset..(x_offset + x_bytes.len())].copy_from_slice(&x_bytes);
        out[y_offset..(y_offset + y_bytes.len())].copy_from_slice(&y_bytes);

        out
    }

    /// Returns `true` if this represents an infinite point.
    pub fn is_infinity(&self) -> bool {
        self.x.is_none() && self.y.is_none()
    }

    /// Adds this EC point to another EC point.
    pub fn add(&self, other: &EcPoint) -> EcPoint {
        self.native_plus(other)
    }

    /// Multiplies this EC point by a scalar value.
    pub fn mul(&self, k: &BigInt) -> EcPoint {
        self.native_times(k)
    }

    /// Negates this EC point.
    pub fn negate(&self) -> EcPoint {
        if self.is_infinity() {
            self.clone()
        } else {
            let p = self.curve.p();
            let y = ((&p - self.y.as_ref().unwrap()) % &p + &p) % &p;
            self.curve.point(self.x.clone(), Some(y))
        }
    }

    fn native_times(&self, k: &BigInt) -> EcPoint {
        crate::bindings::ec::EcPoint::from_public(self.curve.to_string().as_str(), self.uncompressed().as_slice())
            .and_then(|ep| ep.mul(&k.to_signed_bytes_be()))
            .and_then(|ep| ep.to_bytes())
            .map(|bytes| EcPublicKey::new(self.curve.clone(), bytes).to_ec_point())
            .unwrap()
    }

    fn native_plus(&self, other: &EcPoint) -> EcPoint {
        let other_ec = crate::bindings::ec::EcPoint::from_public(other.curve.to_string().as_str(), other.uncompressed().as_slice()).unwrap();

        crate::bindings::ec::EcPoint::from_public(self.curve.to_string().as_str(), self.uncompressed().as_slice())
            .and_then(|ep| ep.add(&other_ec))
            .and_then(|ep| ep.to_bytes())
            .map(|bytes| EcPublicKey::new(self.curve.clone(), bytes).to_ec_point())
            .unwrap()
    }
}

// Conversion to EcPublicKey
impl EcPoint {
    pub fn to_ec_public_key(&self) -> EcPublicKey {
        EcPublicKey::new(self.curve.clone(), self.uncompressed())
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
        let point = EcPoint::new(curve.clone(), None, None);
        assert!(point.is_infinity());
    }

    #[test]
    fn test_regular_point() {
        let curve = EcCurve::BrainpoolP256r1;
        let x = hex_bigint("78028496B5ECAAB3C8B6C12E45DB1E02C9E4D26B4113BC4F015F60C5CCC0D206");
        let y = hex_bigint("A2AE1762A3831C1D20F03F8D1E3C0C39AFE6F09B4D44BBE80CD100987B05F92B");
        let point = EcPoint::new(curve.clone(), Some(x.clone()), Some(y.clone()));
        assert!(!point.is_infinity());
        assert_eq!(Some(x), point.x);
        assert_eq!(Some(y), point.y);
    }

    #[test]
    #[should_panic]
    fn test_invalid_point_coordinates_x_none_y_some() {
        let curve = EcCurve::BrainpoolP256r1;
        EcPoint::new(curve.clone(), None, Some(BigInt::one()));
    }

    #[test]
    #[should_panic]
    fn test_invalid_point_coordinates_x_some_y_none() {
        let curve = EcCurve::BrainpoolP256r1;
        EcPoint::new(curve.clone(), Some(BigInt::one()), None);
    }

    #[test]
    fn test_point_negation() {
        let curve = EcCurve::BrainpoolP256r1;
        let x = hex_bigint("78028496B5ECAAB3C8B6C12E45DB1E02C9E4D26B4113BC4F015F60C5CCC0D206");
        let y = hex_bigint("A2AE1762A3831C1D20F03F8D1E3C0C39AFE6F09B4D44BBE80CD100987B05F92B");
        let point = EcPoint::new(curve.clone(), Some(x.clone()), Some(y.clone()));
        let negated = point.negate();
        assert_eq!(point.x, negated.x);
        let expected_y = ((curve.p() - &y) % curve.p() + curve.p()) % curve.p();
        assert_eq!(Some(expected_y), negated.y);
    }

    #[test]
    fn test_uncompressed_encoding() {
        let curve = EcCurve::BrainpoolP256r1;
        let x = hex_bigint("78028496B5ECAAB3C8B6C12E45DB1E02C9E4D26B4113BC4F015F60C5CCC0D206");
        let y = hex_bigint("A2AE1762A3831C1D20F03F8D1E3C0C39AFE6F09B4D44BBE80CD100987B05F92B");
        let point = EcPoint::new(curve, Some(x), Some(y));
        let uncompressed = point.uncompressed();
        assert_eq!(65, uncompressed.len());
        assert_eq!(0x04, uncompressed[0]);
    }

    #[test]
    #[should_panic]
    fn test_uncompressed_encoding_of_infinity() {
        let curve = EcCurve::BrainpoolP256r1;
        let point = EcPoint::new(curve, None, None);
        point.uncompressed();
    }

    #[test]
    fn test_curve_coordinate_sizes() {
        let x = BigInt::one();
        let y = BigInt::one();
        let p256_point = EcPoint::new(EcCurve::BrainpoolP256r1, Some(x.clone()), Some(y.clone()));
        assert_eq!(65, p256_point.uncompressed().len());

        let p384_point = EcPoint::new(EcCurve::BrainpoolP384r1, Some(x.clone()), Some(y.clone()));
        assert_eq!(97, p384_point.uncompressed().len());

        let p512_point = EcPoint::new(EcCurve::BrainpoolP512r1, Some(x), Some(y));
        assert_eq!(129, p512_point.uncompressed().len());
    }

    #[test]
    fn test_to_ec_public_key() {
        let curve = EcCurve::BrainpoolP256r1;
        let x = hex_bigint("78028496B5ECAAB3C8B6C12E45DB1E02C9E4D26B4113BC4F015F60C5CCC0D206");
        let y = hex_bigint("A2AE1762A3831C1D20F03F8D1E3C0C39AFE6F09B4D44BBE80CD100987B05F92B");
        let point = EcPoint::new(curve.clone(), Some(x), Some(y));
        let public_key = point.to_ec_public_key();
        assert_eq!(curve, public_key.curve);
        assert_eq!(point.uncompressed(), public_key.data);
    }
}
