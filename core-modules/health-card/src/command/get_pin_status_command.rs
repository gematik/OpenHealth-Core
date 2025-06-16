use crate::card::card_key_reference::CardKeyReference;
use crate::card::password_reference::PasswordReference;
use crate::command::health_card_command::HealthCardCommand;
use crate::command::health_card_status::PIN_STATUS;

/// CLA byte for the GET PIN STATUS command
const CLA: u8 = 0x80;

/// INS byte for the GET PIN STATUS command
const GET_PIN_STATUS_INS: u8 = 0x20;

/// P1 parameter with no meaning
const NO_MEANING: u8 = 0x00;

/// Extension trait for HealthCardCommand to provide GET PIN STATUS commands
pub trait GetPinStatusCommand {
    /// Creates a HealthCardCommand for the GET PIN STATUS command.
    /// (gemSpec_COS_3.14.0#14.6.4.1)
    ///
    /// # Arguments
    /// * `password` - The password reference.
    /// * `df_specific` - Indicates if the password object specifies a DF-specific (true) or global (false) reference.
    fn get_pin_status(
        password: &PasswordReference,
        df_specific: bool,
    ) -> HealthCardCommand;
}

impl GetPinStatusCommand for HealthCardCommand {
    fn get_pin_status(
        password: &PasswordReference,
        df_specific: bool,
    ) -> HealthCardCommand {
        HealthCardCommand {
            expected_status: PIN_STATUS.clone(),
            cla: CLA,
            ins: GET_PIN_STATUS_INS,
            p1: NO_MEANING,
            p2: password.calculate_key_reference(df_specific),
            data: None,
            ne: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::card::password_reference::PasswordReference;

    #[test]
    fn test_get_pin_status_command() {
        // Create test object
        let password_ref = PasswordReference::new(3);

        // Test with df_specific = true
        let cmd = HealthCardCommand::get_pin_status(&password_ref, true);
        assert_eq!(cmd.cla, CLA);
        assert_eq!(cmd.ins, GET_PIN_STATUS_INS);
        assert_eq!(cmd.p1, NO_MEANING);
        assert_eq!(cmd.p2, password_ref.calculate_key_reference(true));
        assert_eq!(cmd.data, None);
        assert_eq!(cmd.ne, None);

        // Test with df_specific = false
        let cmd = HealthCardCommand::get_pin_status(&password_ref, false);
        assert_eq!(cmd.cla, CLA);
        assert_eq!(cmd.ins, GET_PIN_STATUS_INS);
        assert_eq!(cmd.p1, NO_MEANING);
        assert_eq!(cmd.p2, password_ref.calculate_key_reference(false));
        assert_eq!(cmd.data, None);
        assert_eq!(cmd.ne, None);
    }
}