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

use crate::error::{CryptoError, CryptoResult};
use crate::ec::ec_point::EcPoint;
use num_bigint::BigInt;
use asn1::asn1_decoder::Asn1Decoder;
use asn1::asn1_tag::UniversalTag;

/// Supported elliptic curves.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum EcCurve {
    BrainpoolP256r1,
    BrainpoolP384r1,
    BrainpoolP512r1,
}

impl EcCurve {
    /// Standard name for the curve.
    pub fn name(&self) -> &'static str {
        match self {
            EcCurve::BrainpoolP256r1 => "brainpoolP256r1",
            EcCurve::BrainpoolP384r1 => "brainpoolP384r1",
            EcCurve::BrainpoolP512r1 => "brainpoolP512r1",
        }
    }

    /// Object identifier (OID) for the curve.
    pub fn oid(&self) -> &'static str {
        match self {
            EcCurve::BrainpoolP256r1 => "1.3.36.3.3.2.8.1.1.7",
            EcCurve::BrainpoolP384r1 => "1.3.36.3.3.2.8.1.1.11",
            EcCurve::BrainpoolP512r1 => "1.3.36.3.3.2.8.1.1.13",
        }
    }

    /// Prime modulus p.
    pub fn p(&self) -> BigInt {
        match self {
            EcCurve::BrainpoolP256r1 => BigInt::parse_bytes(b"A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377", 16).unwrap(),
            EcCurve::BrainpoolP384r1 => BigInt::parse_bytes(b"8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B412B1DA197FB71123ACD3A729901D1A71874700133107EC53", 16).unwrap(),
            EcCurve::BrainpoolP512r1 => BigInt::parse_bytes(b"AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA703308717D4D9B009BC66842AECDA12AE6A380E62881FF2F2D82C68528AA6056583A48F3", 16).unwrap(),
        }
    }
    /// Curve parameter a.
    pub fn a(&self) -> BigInt {
        match self {
            EcCurve::BrainpoolP256r1 => BigInt::parse_bytes(b"7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9", 16).unwrap(),
            EcCurve::BrainpoolP384r1 => BigInt::parse_bytes(b"7BC382C63D8C150C3C72080ACE05AFA0C2BEA28E4FB22787139165EFBA91F90F8AA5814A503AD4EB04A8C7DD22CE2826", 16).unwrap(),
            EcCurve::BrainpoolP512r1 => BigInt::parse_bytes(b"7830A3318B603B89E2327145AC234CC594CBDD8D3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CA", 16).unwrap(),
        }
    }
    /// Curve parameter b.
    pub fn b(&self) -> BigInt {
        match self {
            EcCurve::BrainpoolP256r1 => BigInt::parse_bytes(b"26DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B6", 16).unwrap(),
            EcCurve::BrainpoolP384r1 => BigInt::parse_bytes(b"04A8C7DD22CE28268B39B55416F0447C2FB77DE107DCD2A62E880EA53EEB62D57CB4390295DBC9943AB78696FA504C11", 16).unwrap(),
            EcCurve::BrainpoolP512r1 => BigInt::parse_bytes(b"3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CADC083E67984050B75EBAE5DD2809BD638016F723", 16).unwrap(),
        }
    }
    /// x-coordinate of the base point G.
    pub fn x(&self) -> BigInt {
        match self {
            EcCurve::BrainpoolP256r1 => BigInt::parse_bytes(b"8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262", 16).unwrap(),
            EcCurve::BrainpoolP384r1 => BigInt::parse_bytes(b"1D1C64F068CF45FFA2A63A81B7C13F6B8847A3E77EF14FE3DB7FCAFE0CBD10E8E826E03436D646AAEF87B2E247D4AF1E", 16).unwrap(),
            EcCurve::BrainpoolP512r1 => BigInt::parse_bytes(b"81AEE4BDD82ED9645A21322E9C4C6A9385ED9F70B5D916C1B43B62EEF4D0098EFF3B1F78E2D0D48D50D1687B93B97D5F7C6D5047406A5E688B352209BCB9F822", 16).unwrap(),
        }
    }
    /// y-coordinate of the base point G.
    pub fn y(&self) -> BigInt {
        match self {
            EcCurve::BrainpoolP256r1 => BigInt::parse_bytes(b"547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997", 16).unwrap(),
            EcCurve::BrainpoolP384r1 => BigInt::parse_bytes(b"8ABE1D7520F9C2A45CB1EB8E95CFD55262B70B29FEEC5864E19C054FF99129280E4646217791811142820341263C5315", 16).unwrap(),
            EcCurve::BrainpoolP512r1 => BigInt::parse_bytes(b"7DDE385D566332ECC0EABFA9CF7822FDF209F70024A57B1AA000C55B881F8111B2DCDE494A5F485E5BCA4BD88A2763AED1CA2B2FA8F0540678CD1E0F3AD80892", 16).unwrap(),
        }
    }
    /// Order of the base point.
    pub fn q(&self) -> BigInt {
        match self {
            EcCurve::BrainpoolP256r1 => BigInt::parse_bytes(b"A9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7", 16).unwrap(),
            EcCurve::BrainpoolP384r1 => BigInt::parse_bytes(b"8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B31F166E6CAC0425A7CF3AB6AF6B7FC3103B883202E9046565", 16).unwrap(),
            EcCurve::BrainpoolP512r1 => BigInt::parse_bytes(b"AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA70330870553E5C414CA92619418661197FAC10471DB1D381085DDADDB58796829CA90069", 16).unwrap(),
        }
    }

    /// Return the base point G as an `EcPoint`.
    pub fn g(&self) -> EcPoint {
        EcPoint::finite(self.clone(), self.x(), self.y())
    }

    /// Construct a finite point on this curve from affine coordinates.
    pub fn point(&self, x: impl Into<BigInt>, y: impl Into<BigInt>) -> EcPoint {
        EcPoint::finite(self.clone(), x.into(), y.into())
    }
}

/// EC keypair generation parameters.
pub struct EcKeyPairSpec {
    pub curve: EcCurve,
}

impl EcKeyPairSpec {
    /// Create new keypair parameters for the given curve.
    pub fn new(curve: EcCurve) -> Self {
        Self { curve }
    }
}

/// Elliptic curve public key (uncompressed format).
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct EcPublicKey {
    pub curve: EcCurve,
    pub data: Vec<u8>,
}

impl EcPublicKey {
    /// OID for `id-ecPublicKey` (RFC 5480).
    pub const OID: &'static str = "1.2.840.10045.2.1";

    /// Create a public key from an uncompressed SEC1 encoding.
    pub fn from_uncompressed(curve: EcCurve, data: impl AsRef<[u8]>) -> CryptoResult<Self> {
        let bytes = data.as_ref();

        let required_len = match curve {
            EcCurve::BrainpoolP256r1 => 65,
            EcCurve::BrainpoolP384r1 => 97,
            EcCurve::BrainpoolP512r1 => 129,
        };
        if bytes.len() != required_len {
            return Err(CryptoError::InvalidEcPoint(format!(
                "required length {required_len} != actual length {}",
                bytes.len()
            )));
        }
        if bytes[0] != 0x04 {
            return Err(CryptoError::InvalidEcPoint(
                "not an uncompressed ec point".to_string(),
            ));
        }
        Ok(Self {
            curve,
            data: bytes.to_vec(),
        })
    }
}

impl EcPublicKey {
    /// Convert this public key to an `EcPoint`.
    pub fn to_ec_point(&self) -> EcPoint {
        let coordinate_size = match self.curve {
            EcCurve::BrainpoolP256r1 => 32,
            EcCurve::BrainpoolP384r1 => 48,
            EcCurve::BrainpoolP512r1 => 64,
        };
        let x = BigInt::from_bytes_be(num_bigint::Sign::Plus, &self.data[1..=coordinate_size]);
        let y = BigInt::from_bytes_be(
            num_bigint::Sign::Plus,
            &self.data[(coordinate_size + 1)..=(2 * coordinate_size)],
        );
        EcPoint::finite(self.curve.clone(), x, y)
    }
}

impl EcPublicKey {
    /// Encodes the public key as an ASN.1 DER encoded subject public key info.
    ///
    /// The output will be the raw bytes of the EC public key encoded according to the following ASN.1 structure:
    ///
    /// SubjectPublicKeyInfo  ::=  SEQUENCE  {
    ///   algorithm         AlgorithmIdentifier,
    ///   subjectPublicKey  BIT STRING
    /// }
    pub fn encode_to_asn1(&self) -> CryptoResult<Vec<u8>> {
        Asn1Encoder::write(|scope| {
            // SEQUENCE (SubjectPublicKeyInfo)
            scope.write_tagged_object(UniversalTag::Sequence, UniversalTag::Constructed, |scope| {
                // SEQUENCE (AlgorithmIdentifier)
                scope.write_tagged_object(UniversalTag::Sequence, UniversalTag::Constructed, |scope| {
                    // OID for id-ecPublicKey
                    scope.write_object_identifier(Self::OID)?;
                    // OID for the curve
                    scope.write_object_identifier(self.curve.oid())?;
                    Ok(())
                })?;
                // BIT STRING (public key data)
                scope.write_asn1_bit_string(&self.data, 0)?;
                Ok(())
            })
        }).map_err(|e| CryptoError::Asn1Encoding(e.message))
    }

    /// Parses a ASN.1 DER encoded subject public key info and returns an [EcPublicKey].
    ///
    /// The input should be the raw bytes of the EC public key encoded according to the following ASN.1 structure:
    ///
    /// SubjectPublicKeyInfo  ::=  SEQUENCE  {
    ///   algorithm         AlgorithmIdentifier,
    ///   subjectPublicKey  BIT STRING
    /// }
    pub fn decode_from_asn1(data: &[u8]) -> CryptoResult<Self> {
        Asn1Decoder::new(data).read(|scope| {
            // SEQUENCE (SubjectPublicKeyInfo)
            scope.advance_with_tag(UniversalTag::Sequence, UniversalTag::Constructed, |scope| {
                // Parse AlgorithmIdentifier to get the curve
                let curve = read_ec_curve_from_algorithm_identifier(scope)?;
                // Read the public key point as BIT STRING
                let point = scope.read_bit_string()?;
                scope.skip_to_end()?;

                Ok(EcPublicKey::from_uncompressed(curve, point)
                    .map_err(|e| asn1::asn1_decoder::Asn1DecoderError::new(e.to_string()))?)
            })
        }).map_err(|e| CryptoError::Asn1Decoding(e.message))
    }
}

/// Elliptic curve private key.
#[derive(Clone, PartialEq, Eq)]
pub struct EcPrivateKey {
    pub curve: EcCurve,
    pub data: Vec<u8>,
    pub s: BigInt,
}

impl EcPrivateKey {
    /// Encodes the private key as an ASN.1 DER encoded private key info.
    ///
    /// The output will be the raw bytes of the EC private key encoded
    /// according to the following ASN.1 structure:
    ///
    /// PrivateKeyInfo ::= SEQUENCE {
    ///   version Version,
    ///   privateKeyAlgorithm PrivateKeyAlgorithmIdentifier,
    ///   privateKey PrivateKey,
    ///   attributes [0] IMPLICIT Attributes OPTIONAL
    /// }
    pub fn encode_to_asn1(&self) -> CryptoResult<Vec<u8>> {
        Asn1Encoder::write(|scope| {
            // SEQUENCE (PrivateKeyInfo)
            scope.write_tagged_object(UniversalTag::Sequence, UniversalTag::Constructed, |scope| {
                // version (INTEGER 0)
                scope.write_asn1_int(0)?;

                // SEQUENCE (AlgorithmIdentifier)
                scope.write_tagged_object(UniversalTag::Sequence, UniversalTag::Constructed, |scope| {
                    // OID for id-ecPublicKey
                    scope.write_object_identifier(EcPublicKey::OID)?;
                    // OID for the curve
                    scope.write_object_identifier(self.curve.oid())?;
                    Ok(())
                })?;

                // privateKey (OCTET STRING containing ECPrivateKey)
                scope.write_tagged_object(UniversalTag::OctetString, 0, |scope| {
                    // SEQUENCE (ECPrivateKey)
                    scope.write_tagged_object(UniversalTag::Sequence, UniversalTag::Constructed, |scope| {
                        // version (INTEGER 1)
                        scope.write_asn1_int(1)?;
                        // privateKey (OCTET STRING)
                        scope.write_asn1_octet_string(&self.data)?;
                        Ok(())
                    })
                })?;

                Ok(())
            })
        }).map_err(|e| CryptoError::Asn1Encoding(e.message))
    }

    /// Parses a ASN.1 DER encoded private key and returns an [EcPrivateKey].
    ///
    /// The input should be the raw bytes of the EC private key encoded according to the following ASN.1 structure:
    ///
    /// PrivateKeyInfo ::= SEQUENCE {
    ///   version Version,
    ///   privateKeyAlgorithm PrivateKeyAlgorithmIdentifier,
    ///   privateKey PrivateKey,
    ///   attributes [0] IMPLICIT Attributes OPTIONAL
    /// }
    ///
    /// PrivateKeyAlgorithmIdentifier ::= AlgorithmIdentifier
    ///
    /// PrivateKey ::= OCTET STRING
    ///
    /// ECPrivateKey ::= SEQUENCE {
    ///   version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
    ///   privateKey     OCTET STRING,
    ///   parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
    ///   publicKey  [1] BIT STRING OPTIONAL
    /// }
    pub fn decode_from_asn1(data: &[u8]) -> CryptoResult<Self> {
        Asn1Decoder::new(data).read(|scope| {
            // SEQUENCE (PrivateKeyInfo)
            scope.advance_with_tag(UniversalTag::Sequence, UniversalTag::Constructed, |scope| {
                // version
                scope.read_int_tagged()?;

                // Parse AlgorithmIdentifier to get the curve
                let curve = read_ec_curve_from_algorithm_identifier(scope)?;

                // privateKey (OCTET STRING containing ECPrivateKey)
                scope.advance_with_tag(UniversalTag::OctetString, 0, |scope| {
                    // SEQUENCE (ECPrivateKey)
                    scope.advance_with_tag(UniversalTag::Sequence, UniversalTag::Constructed, |scope| {
                        // version (must be 1)
                        let version = scope.read_int_tagged()?;
                        if version != 1 {
                            return Err(asn1::asn1_decoder::Asn1DecoderError::new(
                                "Unsupported EC private key version".to_string()
                            ));
                        }

                        // privateKey (OCTET STRING)
                        let private_key = scope.read_octet_string()?;
                        scope.skip_to_end()?;

                        Ok(EcPrivateKey {
                            curve,
                            s: BigInt::from_bytes_be(num_bigint::Sign::Plus, &private_key),
                            data: private_key,
                        })
                    })
                })
            })
        }).map_err(|e| CryptoError::Asn1Decoding(e.message))
    }
}


/// Parses an ASN.1 DER encoded algorithm identifier and returns an [EcCurve].
///
/// AlgorithmIdentifier  ::=  SEQUENCE  {
///   algorithm   OBJECT IDENTIFIER,
///   parameters  ANY DEFINED BY algorithm OPTIONAL
/// }
fn read_ec_curve_from_algorithm_identifier(scope: &mut asn1::asn1_decoder::ParserScope) -> Result<EcCurve, asn1::asn1_decoder::Asn1DecoderError> {
    scope.advance_with_tag(UniversalTag::Sequence, UniversalTag::Constructed, |scope| {
        // Read algorithm OID (should be id-ecPublicKey)
        let oid = scope.read_object_identifier()?;
        if oid != EcPublicKey::OID {
            return Err(asn1::asn1_decoder::Asn1DecoderError::new(
                format!("Unexpected OID `{}`. Expected `{}`", oid, EcPublicKey::OID)
            ));
        }

        // Read curve OID
        let curve_oid = scope.read_object_identifier()?;
        scope.skip_to_end()?;

        // Match curve OID to EcCurve
        match curve_oid.as_str() {
            "1.3.36.3.3.2.8.1.1.7" => Ok(EcCurve::BrainpoolP256r1),
            "1.3.36.3.3.2.8.1.1.11" => Ok(EcCurve::BrainpoolP384r1),
            "1.3.36.3.3.2.8.1.1.13" => Ok(EcCurve::BrainpoolP512r1),
            _ => Err(asn1::asn1_decoder::Asn1DecoderError::new(
                format!("Unknown curve with OID `{}`", curve_oid)
            )),
        }
    })
}