// SPDX-FileCopyrightText: Copyright 2025 gematik GmbH
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// *******
//
// For additional notes and disclaimer from gematik and in case of changes by gematik,
// find details in the "Readme" file.

use crate::command::health_card_command::{ExpectedLength, HealthCardCommand};
use crate::command::health_card_status::READ_STATUS;
use crate::command::CommandError;
use crate::identifier::ShortFileIdentifier;

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
    fn read() -> Result<HealthCardCommand, CommandError>;

    /// Creates a HealthCardCommand for the READ BINARY command.
    /// (gemSpec_COS_3.14.0#14.3.2)
    ///
    /// # Arguments
    /// * `offset` - The offset from which to read
    fn read_with_offset(offset: i32) -> Result<HealthCardCommand, CommandError>;

    /// Creates a HealthCardCommand for the READ BINARY command without ShortFileIdentifier.
    /// (gemSpec_COS_3.14.0#14.3.2.1)
    ///
    /// # Arguments
    /// * `offset` - The offset from which to read
    /// * `ne` - The maximum number of bytes to read
    fn read_with_offset_and_length(offset: i32, ne: ExpectedLength) -> Result<HealthCardCommand, CommandError>;

    /// Creates a HealthCardCommand for the READ BINARY command with ShortFileIdentifier.
    /// (gemSpec_COS_3.14.0#14.3.2.2)
    ///
    /// # Arguments
    /// * `sfi` - The ShortFileIdentifier
    fn read_sfi(sfi: ShortFileIdentifier) -> Result<HealthCardCommand, CommandError>;

    /// Creates a HealthCardCommand for the READ BINARY command with ShortFileIdentifier.
    /// (gemSpec_COS_3.14.0#14.3.2.2)
    ///
    /// # Arguments
    /// * `sfi` - The ShortFileIdentifier
    /// * `offset` - The offset from which to read
    fn read_sfi_with_offset(sfi: ShortFileIdentifier, offset: i32) -> Result<HealthCardCommand, CommandError>;

    /// Creates a HealthCardCommand for the READ BINARY command with ShortFileIdentifier.
    /// (gemSpec_COS_3.14.0#14.3.2.2)
    ///
    /// # Arguments
    /// * `sfi` - The ShortFileIdentifier
    /// * `offset` - The offset from which to read
    /// * `ne` - The maximum number of bytes to read
    fn read_sfi_with_offset_and_length(
        sfi: ShortFileIdentifier,
        offset: i32,
        ne: ExpectedLength,
    ) -> Result<HealthCardCommand, CommandError>;
}

impl ReadCommand for HealthCardCommand {
    fn read() -> Result<HealthCardCommand, CommandError> {
        Self::read_with_offset_and_length(0, ExpectedLength::Any)
    }

    fn read_with_offset(offset: i32) -> Result<HealthCardCommand, CommandError> {
        Self::read_with_offset_and_length(offset, ExpectedLength::Any)
    }

    fn read_with_offset_and_length(offset: i32, ne: ExpectedLength) -> Result<HealthCardCommand, CommandError> {
        if !(MIN_OFFSET_RANGE..=MAX_OFFSET_WITHOUT_SFI_RANGE).contains(&offset) {
            return Err(CommandError::OffsetOutOfRange { offset, max: MAX_OFFSET_WITHOUT_SFI_RANGE });
        }

        let p2 = (offset % BYTE_MODULO as i32) as u8;
        let p1 = ((offset - p2 as i32) / BYTE_MODULO as i32) as u8;

        Ok(HealthCardCommand::new(READ_STATUS.clone(), CLA, INS, p1, p2, None, Some(ne)))
    }

    fn read_sfi(sfi: ShortFileIdentifier) -> Result<HealthCardCommand, CommandError> {
        Self::read_sfi_with_offset_and_length(sfi, 0, ExpectedLength::Any)
    }

    fn read_sfi_with_offset(sfi: ShortFileIdentifier, offset: i32) -> Result<HealthCardCommand, CommandError> {
        Self::read_sfi_with_offset_and_length(sfi, offset, ExpectedLength::Any)
    }

    fn read_sfi_with_offset_and_length(
        sfi: ShortFileIdentifier,
        offset: i32,
        ne: ExpectedLength,
    ) -> Result<HealthCardCommand, CommandError> {
        if !(MIN_OFFSET_RANGE..=MAX_OFFSET_WITH_SFI_RANGE).contains(&offset) {
            return Err(CommandError::SfiOffsetOutOfRange { offset, max: MAX_OFFSET_WITH_SFI_RANGE });
        }

        Ok(HealthCardCommand::new(
            READ_STATUS.clone(),
            CLA,
            INS,
            SFI_MARKER + sfi.value(),
            offset as u8,
            None,
            Some(ne),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identifier::ShortFileIdentifier;

    #[test]
    fn test_read_command_without_parameters() {
        let cmd = HealthCardCommand::read().unwrap();
        assert_eq!(cmd.cla, CLA);
        assert_eq!(cmd.ins, INS);
        assert_eq!(cmd.p1, 0x00);
        assert_eq!(cmd.p2, 0x00);
        assert_eq!(cmd.data, None);
        assert_eq!(cmd.ne, Some(ExpectedLength::Any));
    }

    #[test]
    fn test_read_command_with_offset() {
        let cmd = HealthCardCommand::read_with_offset(512).unwrap();
        assert_eq!(cmd.cla, CLA);
        assert_eq!(cmd.ins, INS);
        assert_eq!(cmd.p1, 0x02); // 512 / 256 = 2
        assert_eq!(cmd.p2, 0x00); // 512 % 256 = 0
        assert_eq!(cmd.data, None);
        assert_eq!(cmd.ne, Some(ExpectedLength::Any));
    }

    #[test]
    fn test_read_command_with_offset_and_length() {
        let cmd = HealthCardCommand::read_with_offset_and_length(258, ExpectedLength::Exact(100)).unwrap();
        assert_eq!(cmd.cla, CLA);
        assert_eq!(cmd.ins, INS);
        assert_eq!(cmd.p1, 0x01); // 258 / 256 = 1
        assert_eq!(cmd.p2, 0x02); // 258 % 256 = 2
        assert_eq!(cmd.data, None);
        assert_eq!(cmd.ne, Some(ExpectedLength::Exact(100)));
    }

    #[test]
    fn test_read_command_with_sfi() {
        let sfi = ShortFileIdentifier::new(5).unwrap();
        let cmd = HealthCardCommand::read_sfi(sfi).unwrap();
        assert_eq!(cmd.cla, CLA);
        assert_eq!(cmd.ins, INS);
        assert_eq!(cmd.p1, 0x85); // 0x80 + 0x05
        assert_eq!(cmd.p2, 0x00);
        assert_eq!(cmd.data, None);
        assert_eq!(cmd.ne, Some(ExpectedLength::Any));
    }

    #[test]
    fn test_read_command_with_sfi_and_offset() {
        let sfi = ShortFileIdentifier::new(10).unwrap();
        let cmd = HealthCardCommand::read_sfi_with_offset(sfi, 128).unwrap();
        assert_eq!(cmd.cla, CLA);
        assert_eq!(cmd.ins, INS);
        assert_eq!(cmd.p1, 0x8A); // 0x80 + 0x0A
        assert_eq!(cmd.p2, 128);
        assert_eq!(cmd.data, None);
        assert_eq!(cmd.ne, Some(ExpectedLength::Any));
    }

    #[test]
    fn test_read_command_with_sfi_offset_and_length() {
        let sfi = ShortFileIdentifier::new(30).unwrap(); // Maximum valid SFI
        let cmd = HealthCardCommand::read_sfi_with_offset_and_length(sfi, 255, ExpectedLength::Exact(50)).unwrap();
        assert_eq!(cmd.cla, CLA);
        assert_eq!(cmd.ins, INS);
        assert_eq!(cmd.p1, 0x9E); // 0x80 + 0x1E (30)
        assert_eq!(cmd.p2, 255);
        assert_eq!(cmd.data, None);
        assert_eq!(cmd.ne, Some(ExpectedLength::Exact(50)));
    }

    #[test]
    fn test_read_command_with_invalid_offset() {
        let err = HealthCardCommand::read_with_offset_and_length(-1, ExpectedLength::Exact(100)).unwrap_err();
        assert!(matches!(err, CommandError::OffsetOutOfRange { .. }));
    }

    #[test]
    fn test_read_command_with_too_large_offset() {
        let err = HealthCardCommand::read_with_offset_and_length(0x8000, ExpectedLength::Exact(100)).unwrap_err();
        assert!(matches!(err, CommandError::OffsetOutOfRange { .. }));
    }

    #[test]
    fn test_read_command_with_sfi_and_invalid_offset() {
        let sfi = ShortFileIdentifier::new(10).unwrap();
        let err = HealthCardCommand::read_sfi_with_offset_and_length(sfi, 256, ExpectedLength::Exact(100)).unwrap_err();
        assert!(matches!(err, CommandError::SfiOffsetOutOfRange { .. }));
    }
}
