use crate::key::key::SecretKey;
/// Exception thrown when an error occurs during CMAC operations.
pub struct CmacException {
    pub message: String,
    pub cause: Option<Box<dyn std::error::Error>>,
}

impl std::fmt::Debug for CmacException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::fmt::Display for CmacException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for CmacException {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.cause {
            Some(cause) => Some(cause.as_ref()),
            None => None,
        }
    }
}

/// Enum representing the supported CMAC algorithms.
pub enum CmacAlgorithm {
    Aes,
}

/// Interface representing a CMAC (Cipher-based Message Authentication Code) instance.
pub trait Cmac {
    fn spec(&self) -> &CmacSpec;

    /// Updates the CMAC with the given data.
    fn update(&mut self, data: &[u8]);

    /// Finalizes the CMAC computation and returns the resulting MAC.
    fn final_(&mut self) -> Vec<u8>;
}

/// Specification for creating a CMAC instance.
pub struct CmacSpec {
    pub algorithm: CmacAlgorithm,
}

/// Creates a native CMAC instance based on the given specification and secret key.
pub(crate) fn native_create_cmac(
    _spec: &CmacSpec,
    _secret: &SecretKey,
) -> Box<dyn Cmac> {
    unimplemented!()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::key::SecretKey;
    use crate::utils::test_utils::*;

    fn test_secret() -> SecretKey {
        SecretKey::new(hex_to_bytes("67 AD A7 BE 54 75 0C 47 44 D0 E3 46 66 33 64 05"))
    }

    #[test]
    fn cmac_with_valid_data_expected() {
        let spec = CmacSpec { algorithm: CmacAlgorithm::Aes };
        let secret = test_secret();
        let mut cmac = native_create_cmac(&spec, &secret);
        cmac.update(b"Hello, World!");
        let result = cmac.final_();
        assert_eq!(
            to_hex_string(&result),
            "6B 77 96 A8 0D E9 BB C2 0A B3 E9 95 96 DF EF 43"
        );
    }

    #[test]
    fn cmac_with_empty_data() {
        let spec = CmacSpec { algorithm: CmacAlgorithm::Aes };
        let secret = test_secret();
        let mut cmac = native_create_cmac(&spec, &secret);
        cmac.update(&[]);
        let result = cmac.final_();
        assert_eq!(
            to_hex_string(&result),
            "4F 26 7F 72 08 20 4D 86 B1 AB A8 5A 4C 40 51 E5"
        );
    }

    #[test]
    fn cmac_with_multiple_updates() {
        let spec = CmacSpec { algorithm: CmacAlgorithm::Aes };
        let secret = test_secret();
        let mut cmac = native_create_cmac(&spec, &secret);
        cmac.update(b"Hello, ");
        cmac.update(b"World!");
        let result = cmac.final_();
        assert_eq!(
            to_hex_string(&result),
            "6B 77 96 A8 0D E9 BB C2 0A B3 E9 95 96 DF EF 43"
        );
    }

    #[test]
    #[should_panic]
    fn cmac_final_can_only_be_called_once() {
        let spec = CmacSpec { algorithm: CmacAlgorithm::Aes };
        let secret = test_secret();
        let mut cmac = native_create_cmac(&spec, &secret);
        cmac.update(b"Test data");
        let _ = cmac.final_();
        cmac.final_(); // Should error or panic
    }
}