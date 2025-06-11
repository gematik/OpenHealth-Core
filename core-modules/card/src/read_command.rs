use crate::health_card_command::{HealthCardCommand, EXPECT_ALL_WILDCARD};
use crate::health_card_status::READ_STATUS; // Importiere READ_STATUS
use crate::short_file_identifier::ShortFileIdentifier;

/// CLA byte for the READ BINARY command
const CLA: u8 = 0x00;

/// INS byte for the READ BINARY command
const INS: u8 = 0xB0;

/// Modulo for byte calculations
const BYTE_MODULO: u16 = 256;

/// Marker for Short File Identifier in P1
const SFI_MARKER: u8 = 0x80;

/// Minimum offset range
const MIN_OFFSET_RANGE: i32 = 0;

/// Maximum offset without SFI range
const MAX_OFFSET_WITHOUT_SFI_RANGE: i32 = 0x7FFF;

/// Maximum offset with SFI range
const MAX_OFFSET_WITH_SFI_RANGE: i32 = 255;

/// Extension trait for HealthCardCommand to provide READ BINARY commands
pub trait ReadCommand {
    /// Creates a HealthCardCommand for the READ BINARY command without offset.
    /// (gemSpec_COS_3.14.0#14.3.2)
    fn read() -> HealthCardCommand;

    /// Creates a HealthCardCommand for the READ BINARY command.
    /// (gemSpec_COS_3.14.0#14.3.2)
    ///
    /// # Arguments
    /// * `offset` - The offset from which to read
    fn read_with_offset(offset: i32) -> HealthCardCommand;

    /// Creates a HealthCardCommand for the READ BINARY command without ShortFileIdentifier.
    /// (gemSpec_COS_3.14.0#14.3.2.1)
    ///
    /// # Arguments
    /// * `offset` - The offset from which to read
    /// * `ne` - The maximum number of bytes to read
    fn read_with_offset_and_length(offset: i32, ne: i32) -> HealthCardCommand;

    /// Creates a HealthCardCommand for the READ BINARY command with ShortFileIdentifier.
    /// (gemSpec_COS_3.14.0#14.3.2.2)
    ///
    /// # Arguments
    /// * `sfi` - The ShortFileIdentifier
    fn read_sfi(sfi: ShortFileIdentifier) -> HealthCardCommand;

    /// Creates a HealthCardCommand for the READ BINARY command with ShortFileIdentifier.
    /// (gemSpec_COS_3.14.0#14.3.2.2)
    ///
    /// # Arguments
    /// * `sfi` - The ShortFileIdentifier
    /// * `offset` - The offset from which to read
    fn read_sfi_with_offset(sfi: ShortFileIdentifier, offset: i32) -> HealthCardCommand;

    /// Creates a HealthCardCommand for the READ BINARY command with ShortFileIdentifier.
    /// (gemSpec_COS_3.14.0#14.3.2.2)
    ///
    /// # Arguments
    /// * `sfi` - The ShortFileIdentifier
    /// * `offset` - The offset from which to read
    /// * `ne` - The maximum number of bytes to read
    fn read_sfi_with_offset_and_length(sfi: ShortFileIdentifier, offset: i32, ne: i32) -> HealthCardCommand;
}

impl ReadCommand for HealthCardCommand {
    fn read() -> HealthCardCommand {
        Self::read_with_offset_and_length(0, EXPECT_ALL_WILDCARD)
    }

    fn read_with_offset(offset: i32) -> HealthCardCommand {
        Self::read_with_offset_and_length(offset, EXPECT_ALL_WILDCARD)
    }

    fn read_with_offset_and_length(offset: i32, ne: i32) -> HealthCardCommand {
        assert!(
            (MIN_OFFSET_RANGE..=MAX_OFFSET_WITHOUT_SFI_RANGE).contains(&offset),
            "Offset must be in range [0, 32767]"
        );

        let p2 = (offset % BYTE_MODULO as i32) as u8;
        let p1 = ((offset - p2 as i32) / BYTE_MODULO as i32) as u8;

        HealthCardCommand {
            expected_status: READ_STATUS.clone(), // Verwende das importierte READ_STATUS
            cla: CLA,
            ins: INS,
            p1,
            p2,
            data: None,
            ne: Some(ne as usize),
        }
    }

    fn read_sfi(sfi: ShortFileIdentifier) -> HealthCardCommand {
        Self::read_sfi_with_offset_and_length(sfi, 0, EXPECT_ALL_WILDCARD)
    }

    fn read_sfi_with_offset(sfi: ShortFileIdentifier, offset: i32) -> HealthCardCommand {
        Self::read_sfi_with_offset_and_length(sfi, offset, EXPECT_ALL_WILDCARD)
    }

    fn read_sfi_with_offset_and_length(sfi: ShortFileIdentifier, offset: i32, ne: i32) -> HealthCardCommand {
        assert!(
            (MIN_OFFSET_RANGE..=MAX_OFFSET_WITH_SFI_RANGE).contains(&offset),
            "Offset must be in range [0, 255]"
        );

        HealthCardCommand {
            expected_status: READ_STATUS.clone(), // Verwende das importierte READ_STATUS
            cla: CLA,
            ins: INS,
            p1: SFI_MARKER + sfi.sf_id,
            p2: offset as u8,
            data: None,
            ne: Some(ne as usize),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::short_file_identifier::ShortFileIdentifier;

    #[test]
    fn test_read_command_without_parameters() {
        let cmd = HealthCardCommand::read();
        assert_eq!(cmd.cla, CLA);
        assert_eq!(cmd.ins, INS);
        assert_eq!(cmd.p1, 0x00);
        assert_eq!(cmd.p2, 0x00);
        assert_eq!(cmd.data, None);
        assert_eq!(cmd.ne, Some(EXPECT_ALL_WILDCARD as usize));
    }

    #[test]
    fn test_read_command_with_offset() {
        let cmd = HealthCardCommand::read_with_offset(512);
        assert_eq!(cmd.cla, CLA);
        assert_eq!(cmd.ins, INS);
        assert_eq!(cmd.p1, 0x02); // 512 / 256 = 2
        assert_eq!(cmd.p2, 0x00); // 512 % 256 = 0
        assert_eq!(cmd.data, None);
        assert_eq!(cmd.ne, Some(EXPECT_ALL_WILDCARD as usize));
    }

    #[test]
    fn test_read_command_with_offset_and_length() {
        let cmd = HealthCardCommand::read_with_offset_and_length(258, 100);
        assert_eq!(cmd.cla, CLA);
        assert_eq!(cmd.ins, INS);
        assert_eq!(cmd.p1, 0x01); // 258 / 256 = 1
        assert_eq!(cmd.p2, 0x02); // 258 % 256 = 2
        assert_eq!(cmd.data, None);
        assert_eq!(cmd.ne, Some(100));
    }

    #[test]
    fn test_read_command_with_sfi() {
        let sfi = ShortFileIdentifier::new(5).unwrap();
        let cmd = HealthCardCommand::read_sfi(sfi);
        assert_eq!(cmd.cla, CLA);
        assert_eq!(cmd.ins, INS);
        assert_eq!(cmd.p1, 0x85); // 0x80 + 0x05
        assert_eq!(cmd.p2, 0x00);
        assert_eq!(cmd.data, None);
        assert_eq!(cmd.ne, Some(EXPECT_ALL_WILDCARD as usize));
    }

    #[test]
    fn test_read_command_with_sfi_and_offset() {
        let sfi = ShortFileIdentifier::new(10).unwrap();
        let cmd = HealthCardCommand::read_sfi_with_offset(sfi, 128);
        assert_eq!(cmd.cla, CLA);
        assert_eq!(cmd.ins, INS);
        assert_eq!(cmd.p1, 0x8A); // 0x80 + 0x0A
        assert_eq!(cmd.p2, 128);
        assert_eq!(cmd.data, None);
        assert_eq!(cmd.ne, Some(EXPECT_ALL_WILDCARD as usize));
    }

    #[test]
    fn test_read_command_with_sfi_offset_and_length() {
        let sfi = ShortFileIdentifier::new(30).unwrap(); // Maximum valid SFI
        let cmd = HealthCardCommand::read_sfi_with_offset_and_length(sfi, 255, 50);
        assert_eq!(cmd.cla, CLA);
        assert_eq!(cmd.ins, INS);
        assert_eq!(cmd.p1, 0x9E); // 0x80 + 0x1E (30)
        assert_eq!(cmd.p2, 255);
        assert_eq!(cmd.data, None);
        assert_eq!(cmd.ne, Some(50));
    }

    #[test]
    #[should_panic(expected = "Offset must be in range [0, 32767]")]
    fn test_read_command_with_invalid_offset() {
        HealthCardCommand::read_with_offset_and_length(-1, 100);
    }

    #[test]
    #[should_panic(expected = "Offset must be in range [0, 32767]")]
    fn test_read_command_with_too_large_offset() {
        HealthCardCommand::read_with_offset_and_length(0x8000, 100);
    }

    #[test]
    #[should_panic(expected = "Offset must be in range [0, 255]")]
    fn test_read_command_with_sfi_and_invalid_offset() {
        let sfi = ShortFileIdentifier::new(10).unwrap();
        HealthCardCommand::read_sfi_with_offset_and_length(sfi, 256, 100);
    }
}