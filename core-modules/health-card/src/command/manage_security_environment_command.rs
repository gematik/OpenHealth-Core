use crate::card::card_key_reference::CardKeyReference;
use crate::command::health_card_command::HealthCardCommand;
use crate::command::health_card_status::MANAGE_SECURITY_ENVIRONMENT_STATUS;
use crate::card::pso_algorithm::PsoAlgorithm;
use asn1::Asn1Encoder;
use asn1::tag_class;
use asn1::write_tagged_object;

/// CLA byte for the MANAGE SECURITY ENVIRONMENT command
const CLA: u8 = 0x00;

/// INS byte for the MANAGE SECURITY ENVIRONMENT command
const INS: u8 = 0x22;

/// Mode for setting secret key object (P1)
const MODE_SET_SECRET_KEY_OBJECT_P1: u8 = 0xC1;

/// Mode where the affected list element is external authentication (P2)
const MODE_AFFECTED_LIST_ELEMENT_IS_EXT_AUTH_P2: u8 = 0xA4;

/// Mode for setting private key (P1)
const MODE_SET_PRIVATE_KEY_P1: u8 = 0x41;

/// Mode where the affected list element is signature creation (P2)
const MODE_AFFECTED_LIST_ELEMENT_IS_SIGNATURE_CREATION: u8 = 0xB6;

/// Extension trait for HealthCardCommand to provide MANAGE SECURITY ENVIRONMENT commands
pub trait ManageSecurityEnvironmentCommand {
    /// Creates a HealthCardCommand for the MANAGE SECURITY ENVIRONMENT command
    /// without curves. (gemSpec_COS_3.14.0#14.9.9.7)
    ///
    /// This command is used to set up the security environment for external
    /// authentication.
    ///
    /// # Arguments
    /// * `card_key` - The CardKey to use.
    /// * `df_specific` - true if the key is DF-specific, false otherwise.
    /// * `oid` - The Object Identifier (OID) for the protocol.
    fn manage_sec_env_without_curves<K: CardKeyReference>(
        card_key: &K,
        df_specific: bool,
        oid: &[u8],
    ) -> HealthCardCommand;

    /// Creates a HealthCardCommand for the MANAGE SECURITY ENVIRONMENT command
    /// for signing. (gemSpec_COS_3.14.0#14.9.9.9)
    ///
    /// This command is used to set up the security environment for signing.
    ///
    /// # Arguments
    /// * `pso_algorithm` - The PsoAlgorithm.
    /// * `key` - The CardKey.
    /// * `df_specific` - true if the key is DF-specific, false otherwise.
    fn manage_sec_env_for_signing<K: CardKeyReference>(
        pso_algorithm: PsoAlgorithm,
        key: &K,
        df_specific: bool,
    ) -> HealthCardCommand;
}

impl ManageSecurityEnvironmentCommand for HealthCardCommand {
    fn manage_sec_env_without_curves<K: CardKeyReference>(
        card_key: &K,
        df_specific: bool,
        oid: &[u8],
    ) -> HealthCardCommand {
        let mut encoder = Asn1Encoder::new();
        let data = encoder.write(|encoder| {
            // '80 I2OS(OctetLength(OID), 1) || OID
            write_tagged_object(
                encoder,
                0,
                tag_class::CONTEXT_SPECIFIC,
                |inner_encoder| {
                    inner_encoder.write_bytes(oid);
                    Ok(())
                }
            )?;

            // '83 01 || keyRef'
            write_tagged_object(
                encoder,
                3,
                tag_class::CONTEXT_SPECIFIC,
                |inner_encoder| {
                    inner_encoder.write_byte(card_key.calculate_key_reference(df_specific));
                    Ok(())
                }
            )
        }).unwrap();

        HealthCardCommand {
            expected_status: MANAGE_SECURITY_ENVIRONMENT_STATUS.clone(),
            cla: CLA,
            ins: INS,
            p1: MODE_SET_SECRET_KEY_OBJECT_P1,
            p2: MODE_AFFECTED_LIST_ELEMENT_IS_EXT_AUTH_P2,
            data: Some(data),
            ne: None,
        }
    }

    fn manage_sec_env_for_signing<K: CardKeyReference>(
        pso_algorithm: PsoAlgorithm,
        key: &K,
        df_specific: bool,
    ) -> HealthCardCommand {
        let mut encoder = Asn1Encoder::new();
        let data = encoder.write(|encoder| {
            // '8401 || keyRef'
            write_tagged_object(
                encoder,
                4,
                tag_class::CONTEXT_SPECIFIC,
                |inner_encoder| {
                    inner_encoder.write_byte(key.calculate_key_reference(df_specific));
                    Ok(())
                }
            )?;

            // '8001 || algId'
            write_tagged_object(
                encoder,
                0,
                tag_class::CONTEXT_SPECIFIC,
                |inner_encoder| {
                    inner_encoder.write_byte(pso_algorithm.identifier());
                    Ok(())
                }
            )
        }).unwrap();

        HealthCardCommand {
            expected_status: MANAGE_SECURITY_ENVIRONMENT_STATUS.clone(),
            cla: CLA,
            ins: INS,
            p1: MODE_SET_PRIVATE_KEY_P1,
            p2: MODE_AFFECTED_LIST_ELEMENT_IS_SIGNATURE_CREATION,
            data: Some(data),
            ne: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::card::password_reference::PasswordReference;

    #[test]
    fn test_manage_sec_env_without_curves() {
        // Create test objects
        let password_ref = PasswordReference::new(5);
        let oid = [0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01]; // Example OID

        // Test with df_specific = true
        let cmd = HealthCardCommand::manage_sec_env_without_curves(&password_ref, true, &oid);
        assert_eq!(cmd.cla, CLA);
        assert_eq!(cmd.ins, INS);
        assert_eq!(cmd.p1, MODE_SET_SECRET_KEY_OBJECT_P1);
        assert_eq!(cmd.p2, MODE_AFFECTED_LIST_ELEMENT_IS_EXT_AUTH_P2);
        assert!(cmd.data.is_some());
        assert_eq!(cmd.ne, None);

        // Verify ASN.1 encoding
        let data = cmd.data.unwrap();
        assert!(data.len() > 0);

        // Test with df_specific = false
        let cmd = HealthCardCommand::manage_sec_env_without_curves(&password_ref, false, &oid);
        assert_eq!(cmd.cla, CLA);
        assert_eq!(cmd.ins, INS);
        assert_eq!(cmd.p1, MODE_SET_SECRET_KEY_OBJECT_P1);
        assert_eq!(cmd.p2, MODE_AFFECTED_LIST_ELEMENT_IS_EXT_AUTH_P2);
        assert!(cmd.data.is_some());
        assert_eq!(cmd.ne, None);
    }

    #[test]
    fn test_manage_sec_env_for_signing() {
        // Create test objects
        let password_ref = PasswordReference::new(3);
        let pso_algorithm = PsoAlgorithm::SignVerifyEcdsa;

        // Test with df_specific = true
        let cmd = HealthCardCommand::manage_sec_env_for_signing(pso_algorithm, &password_ref, true);
        assert_eq!(cmd.cla, CLA);
        assert_eq!(cmd.ins, INS);
        assert_eq!(cmd.p1, MODE_SET_PRIVATE_KEY_P1);
        assert_eq!(cmd.p2, MODE_AFFECTED_LIST_ELEMENT_IS_SIGNATURE_CREATION);
        assert!(cmd.data.is_some());
        assert_eq!(cmd.ne, None);

        // Verify ASN.1 encoding
        let data = cmd.data.unwrap();
        assert!(data.len() > 0);

        // Test with df_specific = false
        let cmd = HealthCardCommand::manage_sec_env_for_signing(pso_algorithm, &password_ref, false);
        assert_eq!(cmd.cla, CLA);
        assert_eq!(cmd.ins, INS);
        assert_eq!(cmd.p1, MODE_SET_PRIVATE_KEY_P1);
        assert_eq!(cmd.p2, MODE_AFFECTED_LIST_ELEMENT_IS_SIGNATURE_CREATION);
        assert!(cmd.data.is_some());
        assert_eq!(cmd.ne, None);
    }
}