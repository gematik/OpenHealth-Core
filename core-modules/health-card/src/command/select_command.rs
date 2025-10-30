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

use crate::command::apdu::EXPECTED_LENGTH_WILDCARD_SHORT;
use crate::command::health_card_command::HealthCardCommand;
use crate::command::health_card_status::SELECT_STATUS;
use crate::identifier::{ApplicationIdentifier, FileIdentifier};

const CLA: u8 = 0x00;
const INS: u8 = 0xA4;
const SELECTION_MODE_DF_BY_FID: u8 = 0x01;
const SELECTION_MODE_EF_BY_FID: u8 = 0x02;
const SELECTION_MODE_PARENT: u8 = 0x03;
const SELECTION_MODE_AID: u8 = 0x04;
const RESPONSE_TYPE_NO_RESPONSE: u8 = 0x0C;
const RESPONSE_TYPE_FCP: u8 = 0x04;
const FILE_OCCURRENCE_FIRST: u8 = 0x00;
const FILE_OCCURRENCE_NEXT: u8 = 0x02;

/// Calculate the P2 parameter based on whether FCP is requested and whether to select next occurrence
fn calculate_p2(request_fcp: bool, next_occurrence: bool) -> u8 {
    let response_type = if request_fcp { RESPONSE_TYPE_FCP } else { RESPONSE_TYPE_NO_RESPONSE };

    let file_occurrence = if next_occurrence { FILE_OCCURRENCE_NEXT } else { FILE_OCCURRENCE_FIRST };

    response_type + file_occurrence
}

/// Trait providing SELECT command functionality
pub trait SelectCommand {
    /// Creates a HealthCardCommand for the SELECT command to select the root
    /// of the object system or the parent folder.
    /// (gemSpec_COS_3.14.0#14.2.6.1, gemSpec_COS_3.14.0#14.2.6.11, gemSpec_COS_3.14.0#14.2.6.2)
    ///
    /// # Arguments
    /// * `select_parent_else_root` - If true, selects the parent folder; otherwise, selects the root of the object system.
    /// * `read_first` - If true, requests the File Control Parameter (FCP); otherwise, only selects.
    fn select(select_parent_else_root: bool, read_first: bool) -> HealthCardCommand;

    /// Creates a HealthCardCommand for the SELECT command to select a file with an
    /// Application Identifier (AID), first occurrence, without File Control Parameter.
    /// (gemSpec_COS_3.14.0#14.2.6.5)
    ///
    /// # Arguments
    /// * `aid` - The Application Identifier.
    fn select_aid(aid: &ApplicationIdentifier) -> HealthCardCommand;

    /// Creates a HealthCardCommand for the SELECT command to select a file with an
    /// Application Identifier (AID).
    /// (gemSpec_COS_3.14.0#14.2.6.5 - 14.2.6.8)
    ///
    /// # Arguments
    /// * `aid` - The Application Identifier.
    /// * `select_next_else_first_occurrence` - If true, selects the next occurrence; otherwise, selects the first occurrence.
    /// * `request_fcp` - If true, requests the File Control Parameter (FCP).
    /// * `fcp_length` - Determines the expected size of the response if the File Control Parameter is requested.
    fn select_aid_with_options(
        aid: &ApplicationIdentifier,
        select_next_else_first_occurrence: bool,
        request_fcp: bool,
        fcp_length: i32,
    ) -> HealthCardCommand;

    /// Creates a HealthCardCommand for the SELECT command to select a DF or EF with a
    /// File Identifier (FID).
    /// (gemSpec_COS_3.14.0#14.2.6.9, gemSpec_COS_3.14.0#14.2.6.13)
    ///
    /// # Arguments
    /// * `fid` - The File Identifier.
    /// * `select_df_else_ef` - If true, selects a Dedicated File (DF); otherwise, selects an Elementary File (EF).
    fn select_fid(fid: &FileIdentifier, select_df_else_ef: bool) -> HealthCardCommand;

    /// Creates a HealthCardCommand for the SELECT command to select a DF or EF with a
    /// File Identifier (FID).
    /// (gemSpec_COS_3.14.0#14.2.6.9 - 14.2.6.10, gemSpec_COS_3.14.0#14.2.6.13 - 14.2.6.14)
    ///
    /// # Arguments
    /// * `fid` - The File Identifier.
    /// * `select_df_else_ef` - If true, selects a Dedicated File (DF); otherwise, selects an Elementary File (EF).
    /// * `request_fcp` - If true, requests the File Control Parameter (FCP).
    /// * `fcp_length` - Determines the expected size of the response if the File Control Parameter is requested.
    fn select_fid_with_options(
        fid: &FileIdentifier,
        select_df_else_ef: bool,
        request_fcp: bool,
        fcp_length: i32,
    ) -> HealthCardCommand;
}

impl SelectCommand for HealthCardCommand {
    fn select(select_parent_else_root: bool, read_first: bool) -> HealthCardCommand {
        let p1 = if select_parent_else_root { SELECTION_MODE_PARENT } else { SELECTION_MODE_AID };

        let p2 = calculate_p2(read_first, false);

        let ne = if read_first { Some(EXPECTED_LENGTH_WILDCARD_SHORT) } else { None };

        HealthCardCommand { expected_status: SELECT_STATUS.clone(), cla: CLA, ins: INS, p1, p2, data: None, ne }
    }

    fn select_aid(aid: &ApplicationIdentifier) -> HealthCardCommand {
        Self::select_aid_with_options(aid, false, false, 0)
    }

    fn select_aid_with_options(
        aid: &ApplicationIdentifier,
        select_next_else_first_occurrence: bool,
        request_fcp: bool,
        fcp_length: i32,
    ) -> HealthCardCommand {
        let p2 = calculate_p2(request_fcp, select_next_else_first_occurrence);

        let ne = if request_fcp {
            if fcp_length <= 0 {
                Some(EXPECTED_LENGTH_WILDCARD_SHORT)
            } else {
                Some(fcp_length as usize)
            }
        } else {
            None
        };

        HealthCardCommand {
            expected_status: SELECT_STATUS.clone(),
            cla: CLA,
            ins: INS,
            p1: SELECTION_MODE_AID,
            p2,
            data: Some(aid.aid.clone()),
            ne,
        }
    }

    fn select_fid(fid: &FileIdentifier, select_df_else_ef: bool) -> HealthCardCommand {
        Self::select_fid_with_options(fid, select_df_else_ef, false, 0)
    }

    fn select_fid_with_options(
        fid: &FileIdentifier,
        select_df_else_ef: bool,
        request_fcp: bool,
        fcp_length: i32,
    ) -> HealthCardCommand {
        let p1 = if select_df_else_ef { SELECTION_MODE_DF_BY_FID } else { SELECTION_MODE_EF_BY_FID };

        let p2 = if request_fcp { RESPONSE_TYPE_FCP } else { RESPONSE_TYPE_NO_RESPONSE };

        let ne = if request_fcp {
            if fcp_length <= 0 {
                Some(EXPECTED_LENGTH_WILDCARD_SHORT)
            } else {
                Some(fcp_length as usize)
            }
        } else {
            None
        };

        HealthCardCommand {
            expected_status: SELECT_STATUS.clone(),
            cla: CLA,
            ins: INS,
            p1,
            p2,
            data: Some(fid.get_fid()),
            ne,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identifier::ApplicationIdentifier;
    use crate::identifier::FileIdentifier;

    #[test]
    fn test_select_root() {
        let cmd = HealthCardCommand::select(false, false);
        assert_eq!(cmd.cla, CLA);
        assert_eq!(cmd.ins, INS);
        assert_eq!(cmd.p1, SELECTION_MODE_AID);
        assert_eq!(cmd.p2, RESPONSE_TYPE_NO_RESPONSE);
        assert_eq!(cmd.data, None);
        assert_eq!(cmd.ne, None);
    }

    #[test]
    fn test_select_parent() {
        let cmd = HealthCardCommand::select(true, false);
        assert_eq!(cmd.cla, CLA);
        assert_eq!(cmd.ins, INS);
        assert_eq!(cmd.p1, SELECTION_MODE_PARENT);
        assert_eq!(cmd.p2, RESPONSE_TYPE_NO_RESPONSE);
        assert_eq!(cmd.data, None);
        assert_eq!(cmd.ne, None);
    }

    #[test]
    fn test_select_root_with_fcp() {
        let cmd = HealthCardCommand::select(false, true);
        assert_eq!(cmd.cla, CLA);
        assert_eq!(cmd.ins, INS);
        assert_eq!(cmd.p1, SELECTION_MODE_AID);
        assert_eq!(cmd.p2, RESPONSE_TYPE_FCP);
        assert_eq!(cmd.data, None);
        assert_eq!(cmd.ne, Some(EXPECTED_LENGTH_WILDCARD_SHORT));
    }

    #[test]
    fn test_select_aid() {
        let aid = ApplicationIdentifier { aid: vec![0x12, 0x34, 0x56] };
        let cmd = HealthCardCommand::select_aid(&aid);
        assert_eq!(cmd.cla, CLA);
        assert_eq!(cmd.ins, INS);
        assert_eq!(cmd.p1, SELECTION_MODE_AID);
        assert_eq!(cmd.p2, RESPONSE_TYPE_NO_RESPONSE);
        assert_eq!(cmd.data, Some(vec![0x12, 0x34, 0x56]));
        assert_eq!(cmd.ne, None);
    }

    #[test]
    fn test_select_aid_with_options() {
        let aid = ApplicationIdentifier { aid: vec![0x12, 0x34, 0x56] };
        let cmd = HealthCardCommand::select_aid_with_options(&aid, true, true, 128);
        assert_eq!(cmd.cla, CLA);
        assert_eq!(cmd.ins, INS);
        assert_eq!(cmd.p1, SELECTION_MODE_AID);
        assert_eq!(cmd.p2, RESPONSE_TYPE_FCP + FILE_OCCURRENCE_NEXT);
        assert_eq!(cmd.data, Some(vec![0x12, 0x34, 0x56]));
        assert_eq!(cmd.ne, Some(128));
    }

    #[test]
    fn test_select_fid() {
        // Convert the vector [0xAB, 0xCD] to the u16 value 0xABCD
        let fid = FileIdentifier::new(0xABCD).unwrap();
        let cmd = HealthCardCommand::select_fid(&fid, true);
        assert_eq!(cmd.cla, CLA);
        assert_eq!(cmd.ins, INS);
        assert_eq!(cmd.p1, SELECTION_MODE_DF_BY_FID);
        assert_eq!(cmd.p2, RESPONSE_TYPE_NO_RESPONSE);
        assert_eq!(cmd.data, Some(vec![0xAB, 0xCD]));
        assert_eq!(cmd.ne, None);
    }

    #[test]
    fn test_select_fid_with_options() {
        // Convert the vector [0xAB, 0xCD] to the u16 value 0xABCD
        let fid = FileIdentifier::new(0xABCD).unwrap();
        let cmd = HealthCardCommand::select_fid_with_options(&fid, false, true, 64);
        assert_eq!(cmd.cla, CLA);
        assert_eq!(cmd.ins, INS);
        assert_eq!(cmd.p1, SELECTION_MODE_EF_BY_FID);
        assert_eq!(cmd.p2, RESPONSE_TYPE_FCP);
        assert_eq!(cmd.data, Some(vec![0xAB, 0xCD]));
        assert_eq!(cmd.ne, Some(64));
    }
}
