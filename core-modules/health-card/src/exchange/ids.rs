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

//! Helper constructors for well-known file identifiers on the eGK.

use crate::card::card_key::CardKey;
use crate::card::password_reference::PasswordReference;
use crate::identifier::{ApplicationIdentifier, FileIdentifier, ShortFileIdentifier};

fn application_identifier(bytes: &[u8]) -> ApplicationIdentifier {
    ApplicationIdentifier::new(bytes.to_vec()).expect("constant application identifier must be valid")
}

fn file_identifier(fid: u16) -> FileIdentifier {
    FileIdentifier::new(fid).expect("constant file identifier must be valid")
}

fn short_file_identifier(value: u8) -> ShortFileIdentifier {
    ShortFileIdentifier::new(value).expect("constant short file identifier must be valid")
}

/// AID for `DF.HCA` (gemSpec_ObjSys Section 5.4).
pub fn df_hca_aid() -> ApplicationIdentifier {
    application_identifier(&[0xD2, 0x76, 0x00, 0x00, 0x01, 0x02])
}

/// AID for `DF.ESIGN` (gemSpec_ObjSys Section 5.5).
pub fn df_esign_aid() -> ApplicationIdentifier {
    application_identifier(&[0xA0, 0x00, 0x00, 0x01, 0x67, 0x45, 0x53, 0x49, 0x47, 0x4E])
}

/// File identifier of `EF.CardAccess` in the master file.
pub fn ef_card_access_fid() -> FileIdentifier {
    file_identifier(0x2F01)
}

/// Short file identifier for `EF.Version2`.
pub fn ef_version2_sfid() -> ShortFileIdentifier {
    short_file_identifier(0x1D)
}

/// File identifier for `DF.HCA/EF.VD` containing the insurance data.
pub fn ef_vd_fid() -> FileIdentifier {
    file_identifier(0xE001)
}

/// File identifier for `DF.ESIGN/EF.C.CH.AUT.E256` (certificate of the card holder).
pub fn ef_cch_aut_e256_fid() -> FileIdentifier {
    file_identifier(0xE256)
}

/// Key identifier for the `PrK.ChAutE256` private key in `DF.ESIGN`.
pub fn prk_ch_aut_e256() -> CardKey {
    CardKey::new(0x09)
}

/// Password reference for "MRPIN.H" (home PIN) stored in the master file.
pub fn mr_pin_home_reference() -> PasswordReference {
    PasswordReference::new(0x01)
}

/// Secret key reference used during PACE (CAN key).
pub const SECRET_KEY_REFERENCE: u8 = 0x02;
