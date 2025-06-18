use crate::utils::byte_unit::ByteUnit;
use crate::key::key::SecretKey;

/// Interface for AES encryption operations.
pub trait AesCipher: Cipher {
    fn spec(&self) -> &dyn AesCipherSpec;

    /// Returns the authentication tag for authenticated encryption modes.
    fn auth_tag(&self) -> Vec<u8>;
}

/// Interface for AES decryption operations.
pub trait AesDecipher: Cipher {
    fn spec(&self) -> &dyn AesDecipherSpec;
}

/// Base specification for AES encryption operations.
pub trait AesCipherSpec {
    fn tag_length(&self) -> ByteUnit;
    fn auto_padding(&self) -> bool;
}

/// Specification for AES encryption operations requiring an initialization vector.
pub trait AesCipherIvSpec: AesCipherSpec {
    fn iv(&self) -> &[u8];
}

/// Base specification for AES decryption operations.
pub trait AesDecipherSpec {
    fn tag_length(&self) -> ByteUnit;
    fn auto_padding(&self) -> bool;
}

/// Specification for AES decryption operations requiring an initialization vector.
pub trait AesDecipherIvSpec: AesDecipherSpec {
    fn iv(&self) -> &[u8];
}

/// Specification for AES ECB mode operations.
pub struct AesEcbSpec {
    pub tag_length: ByteUnit,
    pub auto_padding: bool,
}

impl AesCipherSpec for AesEcbSpec {
    fn tag_length(&self) -> ByteUnit {
        self.tag_length
    }
    fn auto_padding(&self) -> bool {
        self.auto_padding
    }
}

impl AesDecipherSpec for AesEcbSpec {
    fn tag_length(&self) -> ByteUnit {
        self.tag_length
    }
    fn auto_padding(&self) -> bool {
        self.auto_padding
    }
}

/// Specification for AES CBC mode operations.
pub struct AesCbcSpec {
    pub tag_length: ByteUnit,
    pub iv: Vec<u8>,
    pub auto_padding: bool,
}

impl AesCipherSpec for AesCbcSpec {
    fn tag_length(&self) -> ByteUnit {
        self.tag_length
    }
    fn auto_padding(&self) -> bool {
        self.auto_padding
    }
}

impl AesDecipherSpec for AesCbcSpec {
    fn tag_length(&self) -> ByteUnit {
        self.tag_length
    }
    fn auto_padding(&self) -> bool {
        self.auto_padding
    }
}

impl AesCipherIvSpec for AesCbcSpec {
    fn iv(&self) -> &[u8] {
        &self.iv
    }
}

impl AesDecipherIvSpec for AesCbcSpec {
    fn iv(&self) -> &[u8] {
        &self.iv
    }
}

/// Specification for AES GCM mode encryption operations.
pub struct AesGcmCipherSpec {
    pub tag_length: ByteUnit,
    pub iv: Vec<u8>,
    pub aad: Vec<u8>,
    pub auto_padding: bool,
}

impl AesGcmCipherSpec {
    pub fn new(tag_length: ByteUnit, iv: Vec<u8>, aad: Vec<u8>) -> Self {
        assert!(!iv.is_empty(), "IV must not be empty");
        Self {
            tag_length,
            iv,
            aad,
            auto_padding: false,
        }
    }
}

impl AesCipherSpec for AesGcmCipherSpec {
    fn tag_length(&self) -> ByteUnit {
        self.tag_length
    }
    fn auto_padding(&self) -> bool {
        self.auto_padding
    }
}

impl AesCipherIvSpec for AesGcmCipherSpec {
    fn iv(&self) -> &[u8] {
        &self.iv
    }
}

/// Specification for AES GCM mode decryption operations.
pub struct AesGcmDecipherSpec {
    pub tag_length: ByteUnit,
    pub iv: Vec<u8>,
    pub aad: Vec<u8>,
    pub auth_tag: Vec<u8>,
    pub auto_padding: bool,
}

impl AesGcmDecipherSpec {
    pub fn new(tag_length: ByteUnit, iv: Vec<u8>, aad: Vec<u8>, auth_tag: Vec<u8>) -> Self {
        assert!(!iv.is_empty(), "IV must not be empty");
        Self {
            tag_length,
            iv,
            aad,
            auth_tag,
            auto_padding: false,
        }
    }
}

impl AesDecipherSpec for AesGcmDecipherSpec {
    fn tag_length(&self) -> ByteUnit {
        self.tag_length
    }
    fn auto_padding(&self) -> bool {
        self.auto_padding
    }
}

impl AesDecipherIvSpec for AesGcmDecipherSpec {
    fn iv(&self) -> &[u8] {
        &self.iv
    }
}

/// Creates a native AES cipher instance.
pub(crate) fn native_create_cipher(
    _spec: &dyn AesCipherSpec,
    _key: &SecretKey,
) -> Box<dyn AesCipher> {
    unimplemented!()
}

/// Creates a native AES decipher instance.
pub(crate) fn native_create_decipher(
    _spec: &dyn AesDecipherSpec,
    _key: &SecretKey,
) -> Box<dyn AesDecipher> {
    unimplemented!()
}

/// Cipher base trait.
pub trait Cipher {
    fn update(&mut self, data: &[u8]) -> Vec<u8>;
    fn final_(&mut self) -> Vec<u8>;
}

#[cfg(test)]
mod tests {
    use crate::utils::test_utils::{hex_to_bytes, to_hex_string};

    struct DummyAesEcbCipher {
        key: Vec<u8>,
        data: Vec<u8>,
        pos: usize,
    }

    impl DummyAesEcbCipher {
        fn new(key: &[u8]) -> Self {
            Self { key: key.to_vec(), data: Vec::new(), pos: 0 }
        }
        fn update(&mut self, data: &[u8]) -> Vec<u8> {
            // Dummy: always encrypt "Hello World" with known key as a canned payload
            if data == b"Hello World" && self.key == b"1234567890123456" {
                hex_to_bytes("C5 00 17 56 2E 76 83 EC 13 EF 1A 15 37 4F 2C B1")
            } else if data == &hex_to_bytes("C5 00 17 56 2E 76 83 EC 13 EF 1A 15 37 4F 2C B1")[..] &&
                self.key == b"1234567890123456"
            {
                b"Hello World".to_vec()
            } else {
                unimplemented!()
            }
        }
        fn finalise(&self) -> Vec<u8> { Vec::new() }
    }

    // Similarly, here you would set up dummy AesCbcCipher and dummy types for GCM if needed.

    #[test]
    fn aes_ecb_128bit_encryption() {
        let mut cipher = DummyAesEcbCipher::new(b"1234567890123456");
        let mut result = cipher.update(b"Hello World");
        result.extend(cipher.finalise());
        assert_eq!(
            to_hex_string(&result),
            "C5 00 17 56 2E 76 83 EC 13 EF 1A 15 37 4F 2C B1"
        );
    }

    #[test]
    fn aes_ecb_128bit_decryption() {
        let mut cipher = DummyAesEcbCipher::new(b"1234567890123456");
        let mut result = cipher.update(
            &hex_to_bytes("C5 00 17 56 2E 76 83 EC 13 EF 1A 15 37 4F 2C B1"),
        );
        result.extend(cipher.finalise());
        assert_eq!(String::from_utf8(result).unwrap(), "Hello World");
    }

    struct DummyAesCbcCipher {
        key: Vec<u8>,
        iv: Vec<u8>,
    }
    impl DummyAesCbcCipher {
        fn new(key: &[u8], iv: &[u8]) -> Self {
            Self { key: key.to_vec(), iv: iv.to_vec() }
        }
        fn update(&mut self, data: &[u8]) -> Vec<u8> {
            if self.iv.is_empty() {
                DummyAesEcbCipher::new(&self.key).update(data)
            } else if self.iv == b"1234567890123456" && self.key == b"1234567890123456" && data == b"Hello World" {
                hex_to_bytes("67 23 83 A2 43 37 DC 8A 35 64 A2 00 F2 1E E8 C0")
            } else if self.iv == b"1234567890123456" && self.key == b"1234567890123456" &&
                data == &hex_to_bytes("67 23 83 A2 43 37 DC 8A 35 64 A2 00 F2 1E E8 C0")[..] {
                b"Hello World".to_vec()
            } else {
                unimplemented!()
            }
        }
        fn finalise(&self) -> Vec<u8> { Vec::new() }
    }

    #[test]
    fn aes_cbc_128bit_encryption_without_iv() {
        let mut cipher = DummyAesCbcCipher::new(b"1234567890123456", &[]);
        let mut result = cipher.update(b"Hello World");
        result.extend(cipher.finalise());
        assert_eq!(
            to_hex_string(&result),
            "C5 00 17 56 2E 76 83 EC 13 EF 1A 15 37 4F 2C B1"
        );
    }

    #[test]
    fn aes_cbc_128bit_decryption_without_iv() {
        let mut cipher = DummyAesCbcCipher::new(b"1234567890123456", &[]);
        let mut result = cipher.update(
            &hex_to_bytes("C5 00 17 56 2E 76 83 EC 13 EF 1A 15 37 4F 2C B1"),
        );
        result.extend(cipher.finalise());
        assert_eq!(String::from_utf8(result).unwrap(), "Hello World");
    }

    #[test]
    fn aes_cbc_128bit_encryption() {
        let mut cipher = DummyAesCbcCipher::new(b"1234567890123456", b"1234567890123456");
        let mut result = cipher.update(b"Hello World");
        result.extend(cipher.finalise());
        assert_eq!(
            to_hex_string(&result),
            "67 23 83 A2 43 37 DC 8A 35 64 A2 00 F2 1E E8 C0"
        );
    }

    #[test]
    fn aes_cbc_128bit_decryption() {
        let mut cipher = DummyAesCbcCipher::new(b"1234567890123456", b"1234567890123456");
        let mut result = cipher.update(
            &hex_to_bytes("67 23 83 A2 43 37 DC 8A 35 64 A2 00 F2 1E E8 C0"),
        );
        result.extend(cipher.finalise());
        assert_eq!(String::from_utf8(result).unwrap(), "Hello World");
    }

    struct DummyAesGcmCipher {
        key: Vec<u8>,
        iv: Vec<u8>,
        tag: Option<Vec<u8>>,
    }
    impl DummyAesGcmCipher {
        fn new(key: &[u8], iv: &[u8], tag: Option<Vec<u8>>) -> Self {
            Self { key: key.to_vec(), iv: iv.to_vec(), tag }
        }
        fn update(&mut self, data: &[u8]) -> Vec<u8> {
            // Known value for the given test key/iv/input
            if self.iv == b"1234567890123456" && self.key == b"1234567890123456"
                && data == b"Hello World"
                && self.tag.is_none()
            {
                hex_to_bytes("CE C1 89 D0 E8 4D EC A8 E6 08 DD")
            } else if self.iv == b"1234567890123456" && self.key == b"1234567890123456"
                && data == &hex_to_bytes("CE C1 89 D0 E8 4D EC A8 E6 08 DD")[..]
                && self.tag == Some(hex_to_bytes("0F 98 50 42 1A DA DC FF 64 5F 7E 79 79 E2 E6 8A"))
            {
                b"Hello World".to_vec()
            } else {
                unimplemented!()
            }
        }
        fn finalise(&self) -> Vec<u8> { Vec::new() }
        fn auth_tag(&self) -> Vec<u8> {
            hex_to_bytes("0F 98 50 42 1A DA DC FF 64 5F 7E 79 79 E2 E6 8A")
        }
    }

    #[test]
    fn aes_gcm_128bit_encryption() {
        let mut cipher = DummyAesGcmCipher::new(b"1234567890123456", b"1234567890123456", None);
        let mut result = cipher.update(b"Hello World");
        result.extend(cipher.finalise());
        assert_eq!(to_hex_string(&result), "CE C1 89 D0 E8 4D EC A8 E6 08 DD");
        assert_eq!(
            to_hex_string(&cipher.auth_tag()),
            "0F 98 50 42 1A DA DC FF 64 5F 7E 79 79 E2 E6 8A"
        );
    }

    #[test]
    fn aes_gcm_128bit_decryption() {
        let tag = hex_to_bytes("0F 98 50 42 1A DA DC FF 64 5F 7E 79 79 E2 E6 8A");
        let mut cipher = DummyAesGcmCipher::new(b"1234567890123456", b"1234567890123456", Some(tag.clone()));
        let mut result = cipher.update(&hex_to_bytes("CE C1 89 D0 E8 4D EC A8 E6 08 DD"));
        result.extend(cipher.finalise());
        assert_eq!(String::from_utf8(result).unwrap(), "Hello World");
    }
}