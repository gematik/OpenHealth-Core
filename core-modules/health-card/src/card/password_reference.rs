/// A password can be a regular password or multireference password:
/// - A "regular password" is used to store a secret, which is usually only known to one cardholder.
///   The COS will allow certain services only if this secret has been successfully presented as
///   part of a user verification. The need for user verification can be turned on (enable) or
///   turned off (disable).
/// - A multireference password allows the use of a secret, which is stored as an at-tributary in a
///   regular password (see (gemSpec_COS_3.14.0#N015.200)), but under conditions that deviate from those of the
///   regular password.

use crate::card::card_key_reference::CardKeyReference;

const MIN_PWD_ID: u8 = 0;
const MAX_PWD_ID: u8 = 31;

/// Represents a reference to a password on the card.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PasswordReference {
    /// The ID of the password.
    pub pwd_id: u8,
}

impl PasswordReference {
    /// Creates a new PasswordReference with the given password ID.
    ///
    /// # Arguments
    /// * `pwd_id` - The ID of the password.
    ///
    /// # Returns
    /// A new PasswordReference instance.
    ///
    /// # Panics
    /// Panics if the password ID is not in the range [0, 31].
    pub fn new(pwd_id: u8) -> Self {
        assert!(
            (MIN_PWD_ID..=MAX_PWD_ID).contains(&pwd_id),
            "Password ID out of range [{},{}]",
            MIN_PWD_ID,
            MAX_PWD_ID
        );
        Self { pwd_id }
    }
}

impl CardKeyReference for PasswordReference {
    /// Calculates the key reference based on whether it's DF-specific.
    /// gemSpec_COS_3.14.0#N072.800
    ///
    /// # Arguments
    /// * `df_specific` - Indicates if the key reference is DF-specific.
    ///
    /// # Returns
    /// The calculated key reference.
    fn calculate_key_reference(&self, df_specific: bool) -> u8 {
        self.pwd_id + if df_specific {
            Self::DF_SPECIFIC_PWD_MARKER
        } else {
            0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_reference_creation() {
        let pwd_ref = PasswordReference::new(5);
        assert_eq!(pwd_ref.pwd_id, 5);
    }

    #[test]
    #[should_panic(expected = "Password ID out of range")]
    fn test_password_reference_out_of_range() {
        PasswordReference::new(32);
    }

    #[test]
    fn test_calculate_key_reference() {
        let pwd_ref = PasswordReference::new(10);

        assert_eq!(pwd_ref.calculate_key_reference(false), 10);

        assert_eq!(
            pwd_ref.calculate_key_reference(true),
            10 + PasswordReference::DF_SPECIFIC_PWD_MARKER
        );
    }
}