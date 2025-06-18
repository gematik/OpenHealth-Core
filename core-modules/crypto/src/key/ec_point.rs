use num_bigint::BigInt;

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
            let p = &self.curve.p();
            let y = (&p - self.y.as_ref().unwrap()).mod_floor(p);
            self.curve.point(self.x.clone(), Some(y))
        }
    }

    // Placeholder for trait contract from Kotlin code
    fn native_times(&self, k: &BigInt) -> EcPoint {
        unimplemented!()
    }

    fn native_plus(&self, other: &EcPoint) -> EcPoint {
        unimplemented!()
    }
}

// Conversion to EcPublicKey
impl EcPoint {
    pub fn to_ec_public_key(&self) -> EcPublicKey {
        EcPublicKey::new(self.curve.clone(), self.uncompressed())
    }
}

// Placeholder structs, as required by translation only.
pub struct EcPublicKey {
    pub curve: EcCurve,
    pub uncompressed: Vec<u8>,
}

impl EcPublicKey {
    pub fn new(curve: EcCurve, uncompressed: Vec<u8>) -> Self {
        EcPublicKey { curve, uncompressed }
    }
}