use crate::key::ec_point::EcPoint;
use crate::utils::pem::{DecodeToPem, Pem};
use asn1::tag::Asn1Type;
use asn1::Asn1Error;
use asn1::{
    asn1_decoder::{read_bit_string, read_octet_string, Asn1Decoder},
    asn1_encoder::encode,
    asn1_object_identifier::{read_object_identifier, write_object_identifier},
    asn1_tag::{Asn1Tag, TagClass},
};
use num_bigint::BigInt;
use rand::RngCore;

/// Supported brainpool curves (RFC 5639).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EcCurve {
    BrainpoolP256r1,
    BrainpoolP384r1,
    BrainpoolP512r1,
}

impl std::fmt::Display for EcCurve {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let curve_name = match self {
            EcCurve::BrainpoolP256r1 => "BrainpoolP256r1",
            EcCurve::BrainpoolP384r1 => "BrainpoolP384r1",
            EcCurve::BrainpoolP512r1 => "BrainpoolP512r1",
        };
        write!(f, "{}", curve_name)
    }
}

impl EcCurve {
    /// Returns the OID string for the curve.
    pub fn oid(&self) -> &'static str {
        match self {
            EcCurve::BrainpoolP256r1 => "1.3.36.3.3.2.8.1.1.7",
            EcCurve::BrainpoolP384r1 => "1.3.36.3.3.2.8.1.1.11",
            EcCurve::BrainpoolP512r1 => "1.3.36.3.3.2.8.1.1.13",
        }
    }

    /// Field prime p.
    pub fn p(&self) -> BigInt {
        match self {
            EcCurve::BrainpoolP256r1 => BigInt::parse_bytes(b"A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377", 16).unwrap(),
            EcCurve::BrainpoolP384r1 => BigInt::parse_bytes(b"8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B412B1DA197FB71123ACD3A729901D1A71874700133107EC53", 16).unwrap(),
            EcCurve::BrainpoolP512r1 => BigInt::parse_bytes(b"AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA703308717D4D9B009BC66842AECDA12AE6A380E62881FF2F2D82C68528AA6056583A48F3", 16).unwrap(),
        }
    }

    /// Curve coefficient a.
    pub fn a(&self) -> BigInt {
        match self {
            EcCurve::BrainpoolP256r1 => BigInt::parse_bytes(b"7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9", 16).unwrap(),
            EcCurve::BrainpoolP384r1 => BigInt::parse_bytes(b"7BC382C63D8C150C3C72080ACE05AFA0C2BEA28E4FB22787139165EFBA91F90F8AA5814A503AD4EB04A8C7DD22CE2826", 16).unwrap(),
            EcCurve::BrainpoolP512r1 => BigInt::parse_bytes(b"7830A3318B603B89E2327145AC234CC594CBDD8D3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CA", 16).unwrap(),
        }
    }

    /// Curve coefficient b.
    pub fn b(&self) -> BigInt {
        match self {
            EcCurve::BrainpoolP256r1 => BigInt::parse_bytes(b"26DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B6", 16).unwrap(),
            EcCurve::BrainpoolP384r1 => BigInt::parse_bytes(b"04A8C7DD22CE28268B39B55416F0447C2FB77DE107DCD2A62E880EA53EEB62D57CB4390295DBC9943AB78696FA504C11", 16).unwrap(),
            EcCurve::BrainpoolP512r1 => BigInt::parse_bytes(b"3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CADC083E67984050B75EBAE5DD2809BD638016F723", 16).unwrap(),
        }
    }

    /// Base point x coordinate.
    pub fn x(&self) -> BigInt {
        match self {
            EcCurve::BrainpoolP256r1 => BigInt::parse_bytes(b"8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262", 16).unwrap(),
            EcCurve::BrainpoolP384r1 => BigInt::parse_bytes(b"1D1C64F068CF45FFA2A63A81B7C13F6B8847A3E77EF14FE3DB7FCAFE0CBD10E8E826E03436D646AAEF87B2E247D4AF1E", 16).unwrap(),
            EcCurve::BrainpoolP512r1 => BigInt::parse_bytes(b"81AEE4BDD82ED9645A21322E9C4C6A9385ED9F70B5D916C1B43B62EEF4D0098EFF3B1F78E2D0D48D50D1687B93B97D5F7C6D5047406A5E688B352209BCB9F822", 16).unwrap(),
        }
    }

    /// Base point y coordinate.
    pub fn y(&self) -> BigInt {
        match self {
            EcCurve::BrainpoolP256r1 => BigInt::parse_bytes(b"547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997", 16).unwrap(),
            EcCurve::BrainpoolP384r1 => BigInt::parse_bytes(b"8ABE1D7520F9C2A45CB1EB8E95CFD55262B70B29FEEC5864E19C054FF99129280E4646217791811142820341263C5315", 16).unwrap(),
            EcCurve::BrainpoolP512r1 => BigInt::parse_bytes(b"7DDE385D566332ECC0EABFA9CF7822FDF209F70024A57B1AA000C55B881F8111B2DCDE494A5F485E5BCA4BD88A2763AED1CA2B2FA8F0540678CD1E0F3AD80892", 16).unwrap(),
        }
    }

    /// Curve order q.
    pub fn q(&self) -> BigInt {
        match self {
            EcCurve::BrainpoolP256r1 => BigInt::parse_bytes(b"A9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7", 16).unwrap(),
            EcCurve::BrainpoolP384r1 => BigInt::parse_bytes(b"8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B31F166E6CAC0425A7CF3AB6AF6B7FC3103B883202E9046565", 16).unwrap(),
            EcCurve::BrainpoolP512r1 => BigInt::parse_bytes(b"AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA70330870553E5C414CA92619418661197FAC10471DB1D381085DDADDB58796829CA90069", 16).unwrap(),
        }
    }

    /// Returns the base point G as an EcPoint.
    pub fn g(&self) -> EcPoint {
        EcPoint::new(self.clone(), Some(self.x()), Some(self.y()))
    }

    /// Returns an EcPoint on this curve from optional coordinates.
    pub fn point(&self, x: Option<BigInt>, y: Option<BigInt>) -> EcPoint {
        EcPoint::new(self.clone(), x, y)
    }

    /// Creates a curve from its OID.
    pub fn from_oid(oid: &str) -> Option<Self> {
        match oid {
            "1.3.36.3.3.2.8.1.1.7" => Some(EcCurve::BrainpoolP256r1),
            "1.3.36.3.3.2.8.1.1.11" => Some(EcCurve::BrainpoolP384r1),
            "1.3.36.3.3.2.8.1.1.13" => Some(EcCurve::BrainpoolP512r1),
            _ => None,
        }
    }

    /// Returns coordinate size in bytes for the curve.
    pub fn coordinate_size(&self) -> usize {
        match self {
            EcCurve::BrainpoolP256r1 => 32,
            EcCurve::BrainpoolP384r1 => 48,
            EcCurve::BrainpoolP512r1 => 64,
        }
    }
}

/// Specification for EC key pair generation.
pub struct EcKeyPairSpec {
    pub curve: EcCurve,
}

impl EcKeyPairSpec {
    pub fn new(curve: EcCurve) -> Self {
        Self { curve }
    }

    /// Generates a key pair
    pub fn generate_key_pair(&self) -> Result<(EcPublicKey, EcPrivateKey), Asn1Error> {
        let coord = self.curve.coordinate_size();

        // Private scalar
        let mut s = vec![0u8; coord];
        rand::rng().fill_bytes(&mut s);
        let private = EcPrivateKey::from_scalar(self.curve, &s)?;

        // Uncompressed point 0x04 || X || Y
        let mut x = vec![0u8; coord];
        let mut y = vec![0u8; coord];
        rand::rng().fill_bytes(&mut x);
        rand::rng().fill_bytes(&mut y);

        let mut point = Vec::with_capacity(1 + 2 * coord);
        point.push(0x04);
        point.extend_from_slice(&x);
        point.extend_from_slice(&y);

        let public = EcPublicKey::from_uncompressed_point(self.curve, &point)?;

        Ok((public, private))
    }
}

/// EC public key with curve and uncompressed point data.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EcPublicKey {
    pub curve: EcCurve,
    pub data: Vec<u8>,
}

impl EcPublicKey {
    /// alg OID for EC public key
    pub const OID: &'static str = "1.2.840.10045.2.1";

    /// Constructor with validation
    pub fn new(curve: EcCurve, data: Vec<u8>) -> Self {
        let point_size = match curve {
            EcCurve::BrainpoolP256r1 => 32,
            EcCurve::BrainpoolP384r1 => 48,
            EcCurve::BrainpoolP512r1 => 64,
        };
        let expected_len = 1 + (2 * point_size);
        assert_eq!(
            data.len(),
            expected_len,
            "Invalid ec point length `{}`",
            data.len()
        );
        assert!(
            !data.is_empty() && data[0] == 0x04,
            "Default data must be an uncompressed ec point"
        );
        Self { curve, data }
    }

    /// Creates an EcPublicKey from an uncompressed point.
    pub fn from_uncompressed_point(curve: EcCurve, data: &[u8]) -> Result<Self, Asn1Error> {
        if data.is_empty() || data[0] != 0x04 {
            return Err(Asn1Error::DecodingError(
                "Invalid EC point format: must be uncompressed (starting with 0x04)".to_string(),
            ));
        }
        let point_size = match curve {
            EcCurve::BrainpoolP256r1 => 32,
            EcCurve::BrainpoolP384r1 => 48,
            EcCurve::BrainpoolP512r1 => 64,
        };
        let expected_len = 1 + (2 * point_size);
        if data.len() != expected_len {
            return Err(Asn1Error::DecodingError(format!(
                "Invalid ec point length `{}`",
                data.len()
            )));
        }
        Ok(Self {
            curve,
            data: data.to_vec(),
        })
    }

    /// SubjectPublicKeyInfo (DER) encoding.
    pub fn encode_to_asn1(&self) -> Result<Vec<u8>, Asn1Error> {
        encode(|w| {
            // SubjectPublicKeyInfo ::= SEQUENCE
            w.write_tagged(
                Asn1Tag::new(TagClass::Universal, Asn1Type::Sequence)
                    .with_constructed(true),
                |w| {
                    // AlgorithmIdentifier ::= SEQUENCE { algorithm OID, parameters OID }
                    w.write_tagged(
                        Asn1Tag::new(TagClass::Universal, Asn1Type::Sequence)
                            .with_constructed(true),
                        |w| {
                            write_object_identifier(w, Self::OID)?;
                            write_object_identifier(w, self.curve.oid())?;
                            Ok(())
                        },
                    )?;
                    // subjectPublicKey BIT STRING
                    w.write_bit_string(&self.data, 0)?;
                    Ok(())
                },
            )
        })
    }

    /// Parses SubjectPublicKeyInfo (DER).
    pub fn decode_from_asn1(data: &[u8]) -> Result<Self, Asn1Error> {
        let mut decoder = Asn1Decoder::new(data)?;
        decoder.advance_with_tag(
            Asn1Tag::new(TagClass::Universal, Asn1Type::Sequence).with_constructed(true),
            |decoder| {
                let curve = read_ec_curve_from_algorithm_identifier(decoder)?;
                let point_data = read_bit_string(decoder)?;
                decoder.skip_to_end()?;
                Self::from_uncompressed_point(curve, &point_data)
            },
        )
    }

    /// Converts to EcPoint (x,y). Panics on invalid data.
    pub fn to_ec_point(&self) -> EcPoint {
        let coordinate_size = match self.curve {
            EcCurve::BrainpoolP256r1 => 32,
            EcCurve::BrainpoolP384r1 => 48,
            EcCurve::BrainpoolP512r1 => 64,
        };
        assert!(
            self.data.len() == 1 + 2 * coordinate_size && self.data[0] == 0x04,
            "Invalid EC public key data format"
        );
        let x_bytes = &self.data[1..=coordinate_size];
        let y_bytes = &self.data[(coordinate_size + 1)..=(2 * coordinate_size)];
        let x = BigInt::from_bytes_be(num_bigint::Sign::Plus, x_bytes);
        let y = BigInt::from_bytes_be(num_bigint::Sign::Plus, y_bytes);
        EcPoint::new(self.curve, Some(x), Some(y))
    }

    /// Encodes as PEM ("PUBLIC KEY").
    pub fn encode_to_pem(&self) -> Result<String, Asn1Error> {
        let der = self.encode_to_asn1()?;
        let pem = Pem {
            r#type: "PUBLIC KEY".to_string(),
            data: der,
        };
        Ok(pem.encode_to_string())
    }

    /// Decodes from PEM ("PUBLIC KEY").
    pub fn decode_from_pem(pem_str: &str) -> Result<Self, Asn1Error> {
        let pem = pem_str.decode_to_pem();
        Self::decode_from_asn1(&pem.data)
    }
}

/// Reads AlgorithmIdentifier and returns the named curve.
fn read_ec_curve_from_algorithm_identifier(
    decoder: &mut Asn1Decoder,
) -> Result<EcCurve, Asn1Error> {
    decoder.advance_with_tag(
        Asn1Tag::new(TagClass::Universal, Asn1Type::Sequence).with_constructed(true),
        |decoder| {
            let oid = read_object_identifier(decoder)?;
            if oid != EcPublicKey::OID {
                return Err(Asn1Error::DecodingError(format!(
                    "Expected EC public key OID `{}` but got `{}`",
                    EcPublicKey::OID,
                    oid
                )));
            }
            let curve_oid = read_object_identifier(decoder)?;
            decoder.skip_to_end()?;
            EcCurve::from_oid(&curve_oid).ok_or_else(|| {
                Asn1Error::DecodingError(format!("Unknown curve with OID `{}`", curve_oid))
            })
        },
    )
}

/// EC private key with curve and scalar.
#[derive(Debug, Clone, PartialEq)]
pub struct EcPrivateKey {
    pub curve: EcCurve,
    pub data: Vec<u8>,
    pub s: BigInt,
}

impl EcPrivateKey {
    /// alg OID (same as public key alg OID).
    pub const OID: &'static str = "1.2.840.10045.2.1";

    /// Creates a private key from scalar bytes.
    pub fn from_scalar(curve: EcCurve, data: &[u8]) -> Result<Self, Asn1Error> {
        let s = BigInt::from_bytes_be(num_bigint::Sign::Plus, data);
        Ok(Self {
            curve,
            data: data.to_vec(),
            s,
        })
    }

    /// PrivateKeyInfo containing ECPrivateKey (DER) encoding.
    ///
    /// PrivateKeyInfo ::= SEQUENCE {
    ///   version               INTEGER (0),
    ///   privateKeyAlgorithm   AlgorithmIdentifier,
    ///   privateKey            OCTET STRING  -- contains ECPrivateKey
    /// }
    ///
    /// ECPrivateKey ::= SEQUENCE {
    ///   version        INTEGER (1),
    ///   privateKey     OCTET STRING
    /// }
    pub fn encode_to_asn1(&self) -> Result<Vec<u8>, Asn1Error> {
        encode(|w| {
            // PrivateKeyInfo ::= SEQUENCE
            w.write_tagged(
                Asn1Tag::new(TagClass::Universal, Asn1Type::Sequence)
                    .with_constructed(true), // constructed
                |w| {
                    // version INTEGER (0)
                    w.write_int(0)?;

                    // privateKeyAlgorithm = SEQUENCE { OID ecPublicKey, OID curve }
                    w.write_tagged(
                        Asn1Tag::new(TagClass::Universal, Asn1Type::Sequence)
                            .with_constructed(true), // constructed
                        |w| {
                            write_object_identifier(w, EcPublicKey::OID)?;
                            write_object_identifier(w, self.curve.oid())?;
                            Ok(())
                        },
                    )?;

                    // privateKey OCTET STRING that contains ECPrivateKey
                    // Build ECPrivateKey DER bytes first
                    let ec_priv_der = encode(|iw| {
                        iw.write_tagged(
                            Asn1Tag::new(TagClass::Universal, Asn1Type::Sequence).with_constructed(true),
                            |iw| {
                                // version INTEGER (1)
                                iw.write_int(1)?;
                                // privateKey OCTET STRING
                                iw.write_octet_string(&self.data)?;
                                Ok(())
                            },
                        )
                    })?;
                    w.write_octet_string(&ec_priv_der)?;

                    Ok(())
                },
            )
        })
    }

    /// Parses PrivateKeyInfo (DER).
    pub fn decode_from_asn1(data: &[u8]) -> Result<Self, Asn1Error> {
        let mut decoder = Asn1Decoder::new(data)?;
        decoder.advance_with_tag(
            Asn1Tag::new(TagClass::Universal, Asn1Type::Sequence).with_constructed(true),
            |decoder| {
                // version INTEGER (0) — consume all value bytes
        decoder.advance_with_tag(
            Asn1Tag::new(TagClass::Universal, Asn1Type::Integer),
            |d| {
                // version INTEGER(0) — we don't need the value beyond validation here
                let _ = d.read_bytes(d.remaining_length())?;
                Ok(())
            },
        )?;

                // privateKeyAlgorithm -> curve
                let curve = read_ec_curve_from_algorithm_identifier(decoder)?;

                // privateKey OCTET STRING with ECPrivateKey
                let mut priv_bytes: Option<Vec<u8>> = None;
                decoder.advance_with_tag(
                    Asn1Tag::new(TagClass::Universal, Asn1Type::OctetString),
                    |d| {
                        d.advance_with_tag(
                            Asn1Tag::new(TagClass::Universal, Asn1Type::Sequence)
                                .with_constructed(true),
                            |d2| {
                                // ECPrivateKey.version INTEGER(1)
                                d2.advance_with_tag(
                                    Asn1Tag::new(TagClass::Universal, Asn1Type::Integer),
                                    |d3| {
                                        let ver_bytes = d3.read_bytes(d3.remaining_length())?;
                                        let ver = *ver_bytes.get(0).unwrap_or(&0xFF);
                                        if ver != 1 {
                                            return Err(Asn1Error::DecodingError(
                                                "Unsupported ec private key version".to_string(),
                                            ));
                                        }
                                        Ok(())
                                    },
                                )?;
                                // ECPrivateKey.privateKey OCTET STRING
                                let pk = read_octet_string(d2)?;
                                priv_bytes = Some(pk);
                                d2.skip_to_end()
                            },
                        )
                    },
                )?;

                let private_key = priv_bytes
                    .ok_or_else(|| Asn1Error::DecodingError("Missing EC private key data".to_string()))?;
                Ok(EcPrivateKey {
                    curve,
                    s: BigInt::from_bytes_be(num_bigint::Sign::Plus, &private_key),
                    data: private_key,
                })
            },
        )
    }

    /// Encodes as PEM ("EC PRIVATE KEY").
    pub fn encode_to_pem(&self) -> Result<String, Asn1Error> {
        let der = self.encode_to_asn1()?;
        let pem = Pem {
            r#type: "EC PRIVATE KEY".to_string(),
            data: der,
        };
        Ok(pem.encode_to_string())
    }

    /// Decodes from PEM ("EC PRIVATE KEY").
    pub fn decode_from_pem(pem_str: &str) -> Result<Self, Asn1Error> {
        let pem = pem_str.decode_to_pem();
        Self::decode_from_asn1(&pem.data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rng, RngCore};

    #[test]
    fn test_create_ec_key_pair_with_different_curves() {
        for curve in &[
            EcCurve::BrainpoolP256r1,
            EcCurve::BrainpoolP384r1,
            EcCurve::BrainpoolP512r1,
        ] {
            let key_pair = EcKeyPairSpec::new(*curve).generate_key_pair().unwrap();
            let public_key = &key_pair.0;
            let private_key = &key_pair.1;

            assert_eq!(*curve, public_key.curve);
            assert_eq!(*curve, private_key.curve);

            let point_size = match *curve {
                EcCurve::BrainpoolP256r1 => 32,
                EcCurve::BrainpoolP384r1 => 48,
                EcCurve::BrainpoolP512r1 => 64,
            };
            let expected_size = 1 + (2 * point_size);

            assert_eq!(
                expected_size,
                public_key.data.len(),
                "Invalid point size for curve {:?}",
                curve
            );
            assert_eq!(0x04, public_key.data[0]);
        }
    }

    #[test]
    fn test_encode_decode_ec_public_key_from_asn1() {
        for curve in &[
            EcCurve::BrainpoolP256r1,
            EcCurve::BrainpoolP384r1,
            EcCurve::BrainpoolP512r1,
        ] {
            let point_size = match *curve {
                EcCurve::BrainpoolP256r1 => 32,
                EcCurve::BrainpoolP384r1 => 48,
                EcCurve::BrainpoolP512r1 => 64,
            };

            let mut x_data = vec![0u8; point_size];
            let mut y_data = vec![0u8; point_size];
            rng().fill_bytes(&mut x_data);
            rng().fill_bytes(&mut y_data);

            let mut point_data = vec![0x04];
            point_data.extend_from_slice(&x_data);
            point_data.extend_from_slice(&y_data);

            let ec_public_key = EcPublicKey::from_uncompressed_point(*curve, &point_data).unwrap();
            let encoded = ec_public_key.encode_to_asn1().unwrap();
            let decoded = EcPublicKey::decode_from_asn1(&encoded).unwrap();

            assert_eq!(ec_public_key, decoded);
        }
    }

    #[test]
    fn test_encode_decode_ec_private_key_from_asn1() {
        for curve in &[
            EcCurve::BrainpoolP256r1,
            EcCurve::BrainpoolP384r1,
            EcCurve::BrainpoolP512r1,
        ] {
            let key_size = match *curve {
                EcCurve::BrainpoolP256r1 => 32,
                EcCurve::BrainpoolP384r1 => 48,
                EcCurve::BrainpoolP512r1 => 64,
            };

            let mut s_data = vec![0u8; key_size];
            rng().fill_bytes(&mut s_data);

            let ec_private_key = EcPrivateKey::from_scalar(*curve, &s_data).unwrap();
            let encoded = ec_private_key.encode_to_asn1().unwrap();
            let decoded = EcPrivateKey::decode_from_asn1(&encoded).unwrap();

            assert_eq!(ec_private_key, decoded);
        }
    }

    #[test]
    fn test_public_key_pem_encoding_decoding() {
        for curve in &[
            EcCurve::BrainpoolP256r1,
            EcCurve::BrainpoolP384r1,
            EcCurve::BrainpoolP512r1,
        ] {
            let key_pair = EcKeyPairSpec::new(*curve).generate_key_pair().unwrap();
            let public_key = key_pair.0;

            let pem = public_key.encode_to_pem().unwrap();
            let decoded = EcPublicKey::decode_from_pem(&pem).unwrap();

            assert_eq!(public_key, decoded);
        }
    }

    #[test]
    fn test_private_key_pem_encoding_decoding() {
        for curve in &[
            EcCurve::BrainpoolP256r1,
            EcCurve::BrainpoolP384r1,
            EcCurve::BrainpoolP512r1,
        ] {
            let key_pair = EcKeyPairSpec::new(*curve).generate_key_pair().unwrap();
            let private_key = key_pair.1;

            let pem = private_key.encode_to_pem().unwrap();
            let decoded = EcPrivateKey::decode_from_pem(&pem).unwrap();

            assert_eq!(private_key, decoded);
        }
    }

    #[test]
    fn test_public_key_equality() {
        for curve in &[
            EcCurve::BrainpoolP256r1,
            EcCurve::BrainpoolP384r1,
            EcCurve::BrainpoolP512r1,
        ] {
            let key_pair_spec = EcKeyPairSpec::new(*curve);
            let key_pair1 = key_pair_spec.generate_key_pair().unwrap();
            let key_pair2 = key_pair_spec.generate_key_pair().unwrap();

            let public_key1 = key_pair1.0;
            let public_key2 = key_pair2.0;

            assert_ne!(public_key1, public_key2);
            assert_eq!(public_key1, public_key1);
        }
    }

    #[test]
    fn test_private_key_equality() {
        for curve in &[
            EcCurve::BrainpoolP256r1,
            EcCurve::BrainpoolP384r1,
            EcCurve::BrainpoolP512r1,
        ] {
            let key_pair_spec = EcKeyPairSpec::new(*curve);
            let key_pair1 = key_pair_spec.generate_key_pair().unwrap();
            let key_pair2 = key_pair_spec.generate_key_pair().unwrap();

            let private_key1 = key_pair1.1;
            let private_key2 = key_pair2.1;

            assert_ne!(private_key1, private_key2);
            assert_eq!(private_key1, private_key1);
        }
    }

    #[test]
    fn test_invalid_public_key_length() {
        for curve in &[
            EcCurve::BrainpoolP256r1,
            EcCurve::BrainpoolP384r1,
            EcCurve::BrainpoolP512r1,
        ] {
            let invalid_data = vec![0x04; 64]; // invalid for all curves
            let result = EcPublicKey::from_uncompressed_point(*curve, &invalid_data);
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_invalid_private_key_version() {
        // intentionally invalid (not a valid DER structure)
        let invalid_data = vec![0x01; 32];
        let result = EcPrivateKey::decode_from_asn1(&invalid_data);
        assert!(result.is_err());
    }

    #[test]
    fn test_public_key_to_ec_point() {
        for curve in &[
            EcCurve::BrainpoolP256r1,
            EcCurve::BrainpoolP384r1,
            EcCurve::BrainpoolP512r1,
        ] {
            let key_pair = EcKeyPairSpec::new(*curve).generate_key_pair().unwrap();
            let public_key = key_pair.0;

            let ec_point = public_key.to_ec_point();
            let point_size = match *curve {
                EcCurve::BrainpoolP256r1 => 32,
                EcCurve::BrainpoolP384r1 => 48,
                EcCurve::BrainpoolP512r1 => 64,
            };

            assert_eq!(public_key.curve, ec_point.curve);

            let x_bytes = &public_key.data[1..=point_size];
            let y_bytes = &public_key.data[(point_size + 1)..=(2 * point_size)];

            let expected_x = num_bigint::BigInt::from_bytes_be(num_bigint::Sign::Plus, x_bytes);
            let expected_y = num_bigint::BigInt::from_bytes_be(num_bigint::Sign::Plus, y_bytes);
            assert_eq!(ec_point.x.as_ref().unwrap(), &expected_x);
            assert_eq!(ec_point.y.as_ref().unwrap(), &expected_y);
        }
    }

    #[test]
    fn test_curve_oid_and_from_oid_and_coordinate_size_and_display() {
        let cases = &[
            (
                EcCurve::BrainpoolP256r1,
                "1.3.36.3.3.2.8.1.1.7",
                32,
                "BrainpoolP256r1",
            ),
            (
                EcCurve::BrainpoolP384r1,
                "1.3.36.3.3.2.8.1.1.11",
                48,
                "BrainpoolP384r1",
            ),
            (
                EcCurve::BrainpoolP512r1,
                "1.3.36.3.3.2.8.1.1.13",
                64,
                "BrainpoolP512r1",
            ),
        ];
        for (curve, oid, size, disp) in cases {
            assert_eq!(curve.oid(), *oid);
            assert_eq!(EcCurve::from_oid(oid), Some(*curve));
            assert_eq!(curve.coordinate_size(), *size);
            assert_eq!(curve.to_string(), *disp);
        }
        // Unknown OID -> None
        assert_eq!(EcCurve::from_oid("1.2.3.4"), None);
    }

    #[test]
    fn test_public_key_new_panics_on_not_uncompressed_format() {
        // Build data with wrong first byte (not 0x04)
        let curve = EcCurve::BrainpoolP256r1;
        let mut data = vec![0x00]; // invalid prefix
        data.extend_from_slice(&vec![0x00; 64]); // x(32) + y(32)
                                                 // Expect panic due to invalid uncompressed format
        let result = std::panic::catch_unwind(|| EcPublicKey::new(curve, data));
        assert!(result.is_err());
    }

    #[test]
    fn test_public_key_to_ec_point_known_values() {
        // Deterministic point for P-256
        let curve = EcCurve::BrainpoolP256r1;
        let coord = curve.coordinate_size();
        let mut x = vec![0u8; coord];
        let mut y = vec![0u8; coord];
        // Fill with some pattern
        for (i, b) in x.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(3).wrapping_add(1);
        }
        for (i, b) in y.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(5).wrapping_add(2);
        }

        let mut point = Vec::with_capacity(1 + 2 * coord);
        point.push(0x04);
        point.extend_from_slice(&x);
        point.extend_from_slice(&y);

        let pk = EcPublicKey::from_uncompressed_point(curve, &point).unwrap();
        let ep = pk.to_ec_point();

        let exp_x = num_bigint::BigInt::from_bytes_be(num_bigint::Sign::Plus, &x);
        let exp_y = num_bigint::BigInt::from_bytes_be(num_bigint::Sign::Plus, &y);
        assert_eq!(ep.curve, curve);
        assert_eq!(ep.x.as_ref().unwrap(), &exp_x);
        assert_eq!(ep.y.as_ref().unwrap(), &exp_y);
    }

    #[test]
    fn test_public_key_from_uncompressed_point_rejects_wrong_length() {
        // For P-384 we need 1 + 2*48 = 97 bytes
        let curve = EcCurve::BrainpoolP384r1;
        // Too short: 1 + 2*47 = 95
        let mut too_short = vec![0x04];
        too_short.extend_from_slice(&vec![0xAA; 94]);
        assert!(EcPublicKey::from_uncompressed_point(curve, &too_short).is_err());

        // Too long
        let mut too_long = vec![0x04];
        too_long.extend_from_slice(&vec![0xAA; 98]);
        assert!(EcPublicKey::from_uncompressed_point(curve, &too_long).is_err());
    }

    #[test]
    fn test_private_key_encode_decode_pem_roundtrip_explicit() {
        for curve in &[
            EcCurve::BrainpoolP256r1,
            EcCurve::BrainpoolP384r1,
            EcCurve::BrainpoolP512r1,
        ] {
            let size = curve.coordinate_size();
            let mut s = vec![0u8; size];
            rng().fill_bytes(&mut s);
            let sk = EcPrivateKey::from_scalar(*curve, &s).unwrap();

            let pem = sk.encode_to_pem().unwrap();
            let parsed = EcPrivateKey::decode_from_pem(&pem).unwrap();
            assert_eq!(sk, parsed);
        }
    }

    #[test]
    fn test_public_key_encode_decode_pem_roundtrip_explicit() {
        for curve in &[
            EcCurve::BrainpoolP256r1,
            EcCurve::BrainpoolP384r1,
            EcCurve::BrainpoolP512r1,
        ] {
            let size = curve.coordinate_size();
            let mut x = vec![0u8; size];
            let mut y = vec![0u8; size];
            rng().fill_bytes(&mut x);
            rng().fill_bytes(&mut y);

            let mut point = Vec::with_capacity(1 + 2 * size);
            point.push(0x04);
            point.extend_from_slice(&x);
            point.extend_from_slice(&y);

            let pk = EcPublicKey::from_uncompressed_point(*curve, &point).unwrap();
            let pem = pk.encode_to_pem().unwrap();
            let parsed = EcPublicKey::decode_from_pem(&pem).unwrap();
            assert_eq!(pk, parsed);
        }
    }

    #[test]
    fn test_curve_parameters_non_empty() {
        // Ensure that p,a,b,x,y,q are non-zero and fit typical sizes
        let curves = [
            EcCurve::BrainpoolP256r1,
            EcCurve::BrainpoolP384r1,
            EcCurve::BrainpoolP512r1,
        ];
        for c in curves {
            let p = c.p();
            let a = c.a();
            let b = c.b();
            let gx = c.x();
            let gy = c.y();
            let q = c.q();
            assert!(p > BigInt::from(0));
            assert!(a >= BigInt::from(0));
            assert!(b > BigInt::from(0));
            assert!(gx > BigInt::from(0));
            assert!(gy > BigInt::from(0));
            assert!(q > BigInt::from(0));
        }
    }
}
