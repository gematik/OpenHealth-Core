use crate::utils::byte_unit::ByteUnit;

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
    _scope: &CryptoScope,
    _key: &SecretKey,
) -> Box<dyn AesCipher> {
    unimplemented!()
}

/// Creates a native AES decipher instance.
pub(crate) fn native_create_decipher(
    _spec: &dyn AesDecipherSpec,
    _scope: &CryptoScope,
    _key: &SecretKey,
) -> Box<dyn AesDecipher> {
    unimplemented!()
}

/// Cipher base trait.
pub trait Cipher {
    fn update(&mut self, data: &[u8]) -> Vec<u8>;
    fn final_(&mut self) -> Vec<u8>;
}