use crate::key::ec_point::EcPoint;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum EcCurve {
    BrainpoolP256r1,
    BrainpoolP384r1,
    BrainpoolP512r1,
}

impl EcCurve {
    pub fn oid(&self) -> &'static str {
        match self {
            EcCurve::BrainpoolP256r1 => "1.3.36.3.3.2.8.1.1.7",
            EcCurve::BrainpoolP384r1 => "1.3.36.3.3.2.8.1.1.11",
            EcCurve::BrainpoolP512r1 => "1.3.36.3.3.2.8.1.1.13",
        }
    }

    pub fn p(&self) -> BigInt {
        match self {
            EcCurve::BrainpoolP256r1 => BigInt::parse_bytes(b"A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377", 16).unwrap(),
            EcCurve::BrainpoolP384r1 => BigInt::parse_bytes(b"8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B412B1DA197FB71123ACD3A729901D1A71874700133107EC53", 16).unwrap(),
            EcCurve::BrainpoolP512r1 => BigInt::parse_bytes(b"AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA703308717D4D9B009BC66842AECDA12AE6A380E62881FF2F2D82C68528AA6056583A48F3", 16).unwrap(),
        }
    }
    pub fn a(&self) -> BigInt {
        match self {
            EcCurve::BrainpoolP256r1 => BigInt::parse_bytes(b"7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9", 16).unwrap(),
            EcCurve::BrainpoolP384r1 => BigInt::parse_bytes(b"7BC382C63D8C150C3C72080ACE05AFA0C2BEA28E4FB22787139165EFBA91F90F8AA5814A503AD4EB04A8C7DD22CE2826", 16).unwrap(),
            EcCurve::BrainpoolP512r1 => BigInt::parse_bytes(b"7830A3318B603B89E2327145AC234CC594CBDD8D3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CA", 16).unwrap(),
        }
    }
    pub fn b(&self) -> BigInt {
        match self {
            EcCurve::BrainpoolP256r1 => BigInt::parse_bytes(b"26DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B6", 16).unwrap(),
            EcCurve::BrainpoolP384r1 => BigInt::parse_bytes(b"04A8C7DD22CE28268B39B55416F0447C2FB77DE107DCD2A62E880EA53EEB62D57CB4390295DBC9943AB78696FA504C11", 16).unwrap(),
            EcCurve::BrainpoolP512r1 => BigInt::parse_bytes(b"3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CADC083E67984050B75EBAE5DD2809BD638016F723", 16).unwrap(),
        }
    }
    pub fn x(&self) -> BigInt {
        match self {
            EcCurve::BrainpoolP256r1 => BigInt::parse_bytes(b"8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262", 16).unwrap(),
            EcCurve::BrainpoolP384r1 => BigInt::parse_bytes(b"1D1C64F068CF45FFA2A63A81B7C13F6B8847A3E77EF14FE3DB7FCAFE0CBD10E8E826E03436D646AAEF87B2E247D4AF1E", 16).unwrap(),
            EcCurve::BrainpoolP512r1 => BigInt::parse_bytes(b"81AEE4BDD82ED9645A21322E9C4C6A9385ED9F70B5D916C1B43B62EEF4D0098EFF3B1F78E2D0D48D50D1687B93B97D5F7C6D5047406A5E688B352209BCB9F822", 16).unwrap(),
        }
    }
    pub fn y(&self) -> BigInt {
        match self {
            EcCurve::BrainpoolP256r1 => BigInt::parse_bytes(b"547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997", 16).unwrap(),
            EcCurve::BrainpoolP384r1 => BigInt::parse_bytes(b"8ABE1D7520F9C2A45CB1EB8E95CFD55262B70B29FEEC5864E19C054FF99129280E4646217791811142820341263C5315", 16).unwrap(),
            EcCurve::BrainpoolP512r1 => BigInt::parse_bytes(b"7DDE385D566332ECC0EABFA9CF7822FDF209F70024A57B1AA000C55B881F8111B2DCDE494A5F485E5BCA4BD88A2763AED1CA2B2FA8F0540678CD1E0F3AD80892", 16).unwrap(),
        }
    }
    pub fn q(&self) -> BigInt {
        match self {
            EcCurve::BrainpoolP256r1 => BigInt::parse_bytes(b"A9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7", 16).unwrap(),
            EcCurve::BrainpoolP384r1 => BigInt::parse_bytes(b"8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B31F166E6CAC0425A7CF3AB6AF6B7FC3103B883202E9046565", 16).unwrap(),
            EcCurve::BrainpoolP512r1 => BigInt::parse_bytes(b"AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA70330870553E5C414CA92619418661197FAC10471DB1D381085DDADDB58796829CA90069", 16).unwrap(),
        }
    }

    pub fn g(&self) -> EcPoint {
        EcPoint::new(self.clone(), Some(self.x()), Some(self.y()))
    }

    pub fn point(&self, x: Option<BigInt>, y: Option<BigInt>) -> EcPoint {
        EcPoint::new(self.clone(), x, y)
    }
}

pub struct EcKeyPairSpec {
    pub curve: EcCurve,
}

impl EcKeyPairSpec {
    pub fn new(curve: EcCurve) -> Self {
        Self { curve }
    }
}

// Trait and placeholder for generating key pairs (expect in Kotlin).
pub trait EcKeyPairGenerator {
    fn generate_key_pair(&self) -> (EcPublicKey, EcPrivateKey);
}

// ====== Public Key =======
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct EcPublicKey {
    pub curve: EcCurve,
    pub data: Vec<u8>,
}

impl EcPublicKey {
    pub const OID: &'static str = "1.2.840.10045.2.1";

    pub fn new(curve: EcCurve, data: Vec<u8>) -> Self {
        let required_len = match curve {
            EcCurve::BrainpoolP256r1 => 65,
            EcCurve::BrainpoolP384r1 => 97,
            EcCurve::BrainpoolP512r1 => 129,
        };
        assert!(data.len() == required_len, "Invalid ec point length `{}`", data.len());
        assert!(data[0] == 0x04, "Default data must be an uncompressed ec point");
        Self { curve, data }
    }
}

impl std::fmt::Debug for EcPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "EcPublicKey(data={:?}, curve={:?})", self.data, self.curve)
    }
}

impl EcPublicKey {
    pub fn to_ec_point(&self) -> EcPoint {
        let coordinate_size = match self.curve {
            EcCurve::BrainpoolP256r1 => 32,
            EcCurve::BrainpoolP384r1 => 48,
            EcCurve::BrainpoolP512r1 => 64,
        };
        let x = BigInt::from_bytes_be(num_bigint::Sign::Plus, &self.data[1..=coordinate_size]);
        let y = BigInt::from_bytes_be(num_bigint::Sign::Plus, &self.data[(coordinate_size + 1)..=(2 * coordinate_size)]);
        EcPoint::new(self.curve.clone(), Some(x), Some(y))
    }

    // Placeholders for encode/decode
    pub fn encode_to_asn1(&self) -> Vec<u8> {
        unimplemented!()
    }
    pub fn encode_to_pem(&self) -> String {
        unimplemented!()
    }
    pub fn decode_from_uncompressed_format(curve: EcCurve, data: Vec<u8>) -> EcPublicKey {
        EcPublicKey::new(curve, data)
    }
    pub fn decode_from_asn1(_data: &[u8]) -> EcPublicKey {
        unimplemented!()
    }
    pub fn decode_from_pem(_data: &str) -> EcPublicKey {
        unimplemented!()
    }
}

// ====== Private Key =======
#[derive(Clone, PartialEq, Eq)]
pub struct EcPrivateKey {
    pub curve: EcCurve,
    pub data: Vec<u8>,
    pub s: BigInt,
}

impl EcPrivateKey {
    pub fn new(curve: EcCurve, data: Vec<u8>) -> Self {
        let s = BigInt::from_bytes_be(num_bigint::Sign::Plus, &data);
        EcPrivateKey { curve, data, s }
    }

    pub fn from_scalar(curve: EcCurve, data: Vec<u8>) -> EcPrivateKey {
        EcPrivateKey::new(curve, data)
    }

    // Placeholders for encode/decode
    pub fn encode_to_asn1(&self) -> Vec<u8> {
        unimplemented!()
    }
    pub fn encode_to_pem(&self) -> String {
        unimplemented!()
    }
    pub fn decode_from_asn1(_data: &[u8]) -> EcPrivateKey {
        unimplemented!()
    }
    pub fn decode_from_pem(_data: &str) -> EcPrivateKey {
        unimplemented!()
    }
}

// ====== ASN.1 function placeholders =======
pub fn read_ec_curve_from_algorithm_identifier(_data: &[u8]) -> EcCurve {
    unimplemented!()
}