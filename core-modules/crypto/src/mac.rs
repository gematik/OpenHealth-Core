use crate::cipher::aes::AesDecipherSpec;
use crate::error::CryptoResult;
use crate::key::key::PrivateKey;
use crate::ossl;
use crate::utils::byte_unit::ByteUnit;

pub enum CmacAlgorithm {
    Aes,
}

impl CmacAlgorithm {
    fn name(&self, key_size: &ByteUnit) -> String {
        match self {
            CmacAlgorithm::Aes => format!("aes-{}-cbc", key_size.bits()),
        }
    }
}

pub enum MacSpec {
    Cmac { algorithm: CmacAlgorithm },
}

impl MacSpec {
    fn cipher(&self, key_size: &ByteUnit) -> String {
        match self {
            MacSpec::Cmac { algorithm } => algorithm.name(key_size),
        }
    }
}

impl MacSpec {
    pub fn create(self, secret: PrivateKey) -> CryptoResult<Mac> {
        let mac = ossl::mac::Mac::create(
            secret.as_ref(),
            "CMAC",
            Some(self.cipher(&secret.size()).as_str()),
            None,
        )?;
        Ok(Mac {
            mac,
            spec: self,
            secret,
        })
    }
}

pub struct Mac {
    mac: ossl::mac::Mac,
    spec: MacSpec,
    secret: PrivateKey,
}

impl Mac {
    pub fn update(&mut self, data: &[u8]) -> CryptoResult<()> {
        self.mac.update(data)?;
        Ok(())
    }
    
    pub fn finalize(&mut self) -> CryptoResult<Vec<u8>> {
        Ok(self.mac.finalize()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::key::PrivateKey;

    // RFC 4493 / SP 800-38B test key
    const K128_HEX: &str = "2B 7E 15 16 28 AE D2 A6 AB F7 15 88 09 CF 4F 3C";

    // Messages from RFC 4493
    const M0_HEX: &str = ""; // empty
    const M16_HEX: &str = "6B C1 BE E2 2E 40 9F 96 E9 3D 7E 11 73 93 17 2A";
    const M64_HEX: &str = concat!(
        "6B C1 BE E2 2E 40 9F 96 E9 3D 7E 11 73 93 17 2A",
        " AE 2D 8A 57 1E 03 AC 9C 9E B7 6F AC 45 AF 8E 51",
        " 30 C8 1C 46 A3 5C E4 11 E5 FB C1 19 1A 0A 52 EF",
        " F6 9F 24 45 DF 4F 9B 17 AD 2B 41 7B E6 6C 37 10"
    );

    // Expected tags (RFC 4493)
    const T_M0_HEX: &str = "BB 1D 69 29 E9 59 37 28 7F A3 7D 12 9B 75 67 46";
    const T_M16_HEX: &str = "07 0A 16 B4 6B 4D 41 44 F7 9B DD 9D D0 4A 28 7C";
    const T_M64_HEX: &str = "51 F0 BE BF 7E 3B 9D 92 FC 49 74 17 79 36 3C FE";

    fn hex_to_bytes(s: &str) -> Vec<u8> {
        s.split_whitespace()
            .filter(|h| !h.is_empty())
            .map(|h| u8::from_str_radix(h, 16).unwrap())
            .collect()
    }

    fn to_hex(bytes: &[u8]) -> String {
        bytes
            .iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<_>>()
            .join(" ")
    }

    fn mac_aes128_tag(msg_hex: &str) -> Vec<u8> {
        let key = PrivateKey::new(hex_to_bytes(K128_HEX));
        let spec = MacSpec::Cmac {
            algorithm: CmacAlgorithm::Aes,
        };
        let mut mac = spec.create(key).unwrap();

        // NOTE: `Mac` currently wraps `ossl::mac::Mac` without passthrough methods.
        // Because tests live in the same module, we can access the private field.
        mac.update(&hex_to_bytes(msg_hex)).unwrap();
        mac.finalize().unwrap()
    }

    #[test]
    fn cmac_aes128_empty_message() {
        let tag = mac_aes128_tag(M0_HEX);
        assert_eq!(to_hex(&tag), T_M0_HEX);
    }

    #[test]
    fn cmac_aes128_one_block() {
        let tag = mac_aes128_tag(M16_HEX);
        assert_eq!(to_hex(&tag), T_M16_HEX);
    }

    #[test]
    fn cmac_aes128_four_blocks() {
        let tag = mac_aes128_tag(M64_HEX);
        assert_eq!(to_hex(&tag), T_M64_HEX);
    }
}
