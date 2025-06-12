/// The format 2 PIN block has been specified for use with IC cards. The format 2 PIN block shall only be used in
/// an offline environment and shall not be used for online PIN verification. This PIN block is constructed by
/// concatenation of two fields: the plain text PIN field and the filler field.
///
/// See "ISO 9564-1"

const NIBBLE_SIZE: u8 = 4;
const MIN_PIN_LEN: usize = 4; // specSpec_COS#N008.000
const MAX_PIN_LEN: usize = 12; // specSpec_COS#N008.000
const FORMAT_PIN_2_ID: u8 = 0x02 << NIBBLE_SIZE; // specSpec_COS#N008.100
const FORMAT2_PIN_SIZE: usize = 8;
const FORMAT2_PIN_FILLER: u8 = 0x0F;
const MIN_DIGIT: u8 = 0; // specSpec_COS#N008.000
const MAX_DIGIT: u8 = 9; // specSpec_COS#N008.000
const STRING_INT_OFFSET: u8 = 48;

/// Represents an encrypted PIN in format 2.
///
/// The format 2 PIN block is used with IC cards in an offline environment and is constructed by
/// concatenating the plain text PIN field and a filler field.
#[derive(Clone, Debug)]
pub struct EncryptedPinFormat2 {
    pub bytes: Vec<u8>,
}

impl EncryptedPinFormat2 {
    /// Creates a new EncryptedPinFormat2 from a PIN string.
    ///
    /// # Arguments
    /// * `pin` - The PIN string to be encrypted. The PIN must be between 4 and 12 digits long.
    pub fn new(pin: &str) -> Self {
        let int_pin: Vec<u8> = pin
            .chars()
            .map(|c| {
                let digit = c as u8 - STRING_INT_OFFSET;
                assert!(
                    (MIN_DIGIT..=MAX_DIGIT).contains(&digit),
                    "PIN digit value is out of range of a decimal digit: {}", c
                );
                digit
            })
            .collect();

        assert!(
            int_pin.len() >= MIN_PIN_LEN,
            "PIN length is too short, min length is {}, but was {}",
            MIN_PIN_LEN,
            int_pin.len()
        );
        assert!(
            int_pin.len() <= MAX_PIN_LEN,
            "PIN length is too long, max length is {}, but was {}",
            MAX_PIN_LEN,
            int_pin.len()
        );

        let mut format2 = [0u8; FORMAT2_PIN_SIZE]; // specSpec_COS#N008.100
        format2[0] = FORMAT_PIN_2_ID + int_pin.len() as u8;

        for (i, &digit) in int_pin.iter().enumerate() {
            if (i + 2) % 2 == 0 {
                format2[1 + i / 2] += digit << NIBBLE_SIZE;
            } else {
                format2[1 + i / 2] += digit;
            }
        }

        for i in int_pin.len()..(2 * FORMAT2_PIN_SIZE - 2) {
            if i % 2 == 0 {
                format2[1 + i / 2] += FORMAT2_PIN_FILLER << NIBBLE_SIZE;
            } else {
                format2[1 + i / 2] += FORMAT2_PIN_FILLER;
            }
        }

        Self {
            bytes: format2.to_vec(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypted_pin_format2_creation() {
        let pin = "1234";
        let encrypted = EncryptedPinFormat2::new(pin);

        // First byte should be 0x24 (FORMAT_PIN_2_ID + pin length)
        assert_eq!(encrypted.bytes[0], 0x24);
        assert_eq!(encrypted.bytes.len(), FORMAT2_PIN_SIZE);
    }

    #[test]
    fn test_encrypted_pin_format2_with_longer_pin() {
        let pin = "123456";
        let encrypted = EncryptedPinFormat2::new(pin);

        assert_eq!(encrypted.bytes[0], 0x26);
    }

    #[test]
    #[should_panic(expected = "PIN length is too short")]
    fn test_encrypted_pin_format2_too_short() {
        EncryptedPinFormat2::new("123");
    }

    #[test]
    #[should_panic(expected = "PIN length is too long")]
    fn test_encrypted_pin_format2_too_long() {
        EncryptedPinFormat2::new("1234567890123");
    }

    #[test]
    #[should_panic(expected = "PIN digit value is out of range")]
    fn test_encrypted_pin_format2_invalid_digit() {
        EncryptedPinFormat2::new("123a");
    }

    #[test]
    fn test_specific_pin_value() {
        let pin = "1234";
        let encrypted = EncryptedPinFormat2::new(pin);
        
        assert_eq!(encrypted.bytes[0], 0x24);
        assert_eq!(encrypted.bytes[1], 0x12);
        assert_eq!(encrypted.bytes[2], 0x34);
        assert_eq!(encrypted.bytes[3], 0xFF);
        assert_eq!(encrypted.bytes[4], 0xFF);
        assert_eq!(encrypted.bytes[5], 0xFF);
        assert_eq!(encrypted.bytes[6], 0xFF);
        assert_eq!(encrypted.bytes[7], 0xFF);
    }
}