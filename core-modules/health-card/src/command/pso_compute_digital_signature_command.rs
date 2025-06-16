use crate::command::health_card_command::{HealthCardCommand, EXPECT_ALL_WILDCARD};
use crate::command::health_card_status::PSO_COMPUTE_DIGITAL_SIGNATURE_STATUS;

/// CLA byte for the PSO COMPUTE DIGITAL SIGNATURE command
const CLA: u8 = 0x00;

/// INS byte for the PSO COMPUTE DIGITAL SIGNATURE command
const INS: u8 = 0x2A;

/// P1 parameter for the PSO COMPUTE DIGITAL SIGNATURE command
const P1: u8 = 0x9E;

/// P2 parameter for the PSO COMPUTE DIGITAL SIGNATURE command
const P2: u8 = 0x9A;

/// Extension trait for HealthCardCommand to provide PSO COMPUTE DIGITAL SIGNATURE command
pub trait PsoComputeDigitalSignatureCommand {
    /// Creates a HealthCardCommand for the PSO COMPUTE DIGITAL SIGNATURE command.
    /// (gemSpec_COS_3.14.0#14.8.2)
    ///
    /// # Arguments
    /// * `data_to_be_signed` - The data to be signed.
    fn pso_compute_digital_signature(data_to_be_signed: &[u8]) -> HealthCardCommand;
}

impl PsoComputeDigitalSignatureCommand for HealthCardCommand {
    fn pso_compute_digital_signature(data_to_be_signed: &[u8]) -> HealthCardCommand {
        HealthCardCommand {
            expected_status: PSO_COMPUTE_DIGITAL_SIGNATURE_STATUS.clone(),
            cla: CLA,
            ins: INS,
            p1: P1,
            p2: P2,
            data: Some(data_to_be_signed.to_vec()),
            ne: Some(EXPECT_ALL_WILDCARD as usize),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pso_compute_digital_signature() {
        // Test with simple data
        let data = [0x01, 0x02, 0x03, 0x04];
        let cmd = HealthCardCommand::pso_compute_digital_signature(&data);

        assert_eq!(cmd.cla, CLA);
        assert_eq!(cmd.ins, INS);
        assert_eq!(cmd.p1, P1);
        assert_eq!(cmd.p2, P2);
        assert_eq!(cmd.data, Some(data.to_vec()));
        assert_eq!(cmd.ne, Some(EXPECT_ALL_WILDCARD as usize));

        // Test with empty data
        let empty_data: [u8; 0] = [];
        let cmd = HealthCardCommand::pso_compute_digital_signature(&empty_data);

        assert_eq!(cmd.cla, CLA);
        assert_eq!(cmd.ins, INS);
        assert_eq!(cmd.p1, P1);
        assert_eq!(cmd.p2, P2);
        assert_eq!(cmd.data, Some(vec![]));
        assert_eq!(cmd.ne, Some(EXPECT_ALL_WILDCARD as usize));

        // Test with longer data
        let long_data = (0..100).map(|i| i as u8).collect::<Vec<u8>>();
        let cmd = HealthCardCommand::pso_compute_digital_signature(&long_data);

        assert_eq!(cmd.cla, CLA);
        assert_eq!(cmd.ins, INS);
        assert_eq!(cmd.p1, P1);
        assert_eq!(cmd.p2, P2);
        assert_eq!(cmd.data, Some(long_data.clone()));
        assert_eq!(cmd.ne, Some(EXPECT_ALL_WILDCARD as usize));
    }
}