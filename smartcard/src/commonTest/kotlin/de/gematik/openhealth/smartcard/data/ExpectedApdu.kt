/*
 * Copyright (c) 2024 gematik GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package de.gematik.openhealth.smartcard.data

import de.gematik.openhealth.smartcard.hexSpaceFormat
import de.gematik.openhealth.smartcard.hexUppercaseFormat

fun getExpectedApdu(
    command: String,
    value: Boolean?,
): String =
    EXPECTED_APDU
        .find { command in it }!!
        .getValue(command)
        .getValue("apdu${if (value == null) "" else "-$value"}")
        .hexToByteArray(hexUppercaseFormat)
        .toHexString(hexSpaceFormat)

private val EXPECTED_APDU =
    listOf(
        // ------------------------------------------------------------------------------------------------------------------------------------------
        // ActivateCommand()
        mapOf("ACTIVATECOMMAND_APDU-1" to mapOf("apdu" to "00440000")),
        // ActivateCommand(byte[] reference) throws IOException
        mapOf("ACTIVATECOMMAND_APDU-2" to mapOf("apdu" to "0044210003830100")),
        // ActivateCommand(Key key, boolean dfSpecific)
        mapOf(
            "ACTIVATECOMMAND_APDU-3" to
                mapOf(
                    "apdu-true" to "00442089",
                    "apdu-false" to "00442009",
                ),
        ),
        // ActivateCommand(Password password, boolean dfSpecific)
        mapOf(
            "ACTIVATECOMMAND_APDU-4" to
                mapOf(
                    "apdu-true" to "00441081",
                    "apdu-false" to "00441001",
                ),
        ),
        // ------------------------------------------------------------------------------------------------------------------------------------------
        // ActivateRecordCommand(int recordNumber, boolean activateAllRecordsStartingFromRecordNumber)
        mapOf(
            "ACTIVATERECORDCOMMAND_APDU-1" to
                mapOf("apdu-true" to "00080105", "apdu-false" to "00080104"),
        ),
        // ActivateRecordCommand(ShortFileIdentifier sfi, int recordNumber, boolean activateAllRecordsStartingFromRecordNumber)
        mapOf(
            "ACTIVATERECORDCOMMAND_APDU-2" to
                mapOf("apdu-true" to "000801ED", "apdu-false" to "000801EC"),
        ),
        // ------------------------------------------------------------------------------------------------------------------------------------------
        // AppendRecordCommand(byte[] data)
        mapOf("APPENDRECORDCOMMAND_APDU-1" to mapOf("apdu" to "00E200000100")),
        // AppendRecordCommand(ShortFileIdentifier sfi, byte[] data)
        mapOf("APPENDRECORDCOMMAND_APDU-2" to mapOf("apdu" to "00E200E80100")),
        // ------------------------------------------------------------------------------------------------------------------------------------------
        // ChangeReferenceDataCommand(Password password, boolean dfSpecific, Format2Pin newSecret)
        mapOf(
            "CHANGEREFERENCEDATACOMMAND_APDU-1" to
                mapOf(
                    "apdu-true" to "002401810826123456FFFFFFFF",
                    "apdu-false" to "002401010826123456FFFFFFFF",
                ),
        ),
        // ChangeReferenceDataCommand(Password password, boolean dfSpecific, Format2Pin oldSecret, Format2Pin newSecret)
        mapOf(
            "CHANGEREFERENCEDATACOMMAND_APDU-2" to
                mapOf(
                    "apdu-true" to "002400811026123456FFFFFFFF26123456FFFFFFFF",
                    "apdu-false" to "002400011026123456FFFFFFFF26123456FFFFFFFF",
                ),
        ),
        // ------------------------------------------------------------------------------------------------------------------------------------------
        // DeactivateCommand()
        mapOf("DEACTIVATECOMMAND_APDU-1" to mapOf("apdu" to "00040000")),
        // DeactivateCommand(Key key, boolean dfSpecific)
        mapOf(
            "DEACTIVATECOMMAND_APDU-2" to
                mapOf("apdu-true" to "00042089", "apdu-false" to "00042009"),
        ),
        // DeactivateCommand(byte[] reference) throws IOException
        mapOf("DEACTIVATECOMMAND_APDU-3" to mapOf("apdu" to "0004210003830100")),
        // DeactivateCommand(Password password, boolean dfSpecific)
        mapOf(
            "DEACTIVATECOMMAND_APDU-4" to
                mapOf("apdu-true" to "00041081", "apdu-false" to "00041001"),
        ),
        // ------------------------------------------------------------------------------------------------------------------------------------------
        // DeactivateRecordCommand(int recordNumber, boolean deactivateAllRecordsStartingFromRecordNumber)
        mapOf(
            "DEACTIVATERECORDCOMMAND_APDU-1" to
                mapOf("apdu-true" to "00060105", "apdu-false" to "00060104"),
        ),
        // DeactivateRecordCommand(ShortFileIdentifier sfi, int recordNumber, boolean deactivateAllRecordsStartingFromRecordNumber)
        mapOf(
            "DEACTIVATERECORDCOMMAND_APDU-2" to
                mapOf("apdu-true" to "000601ED", "apdu-false" to "000601EC"),
        ),
        // ------------------------------------------------------------------------------------------------------------------------------------------
        // DeleteCommand
        mapOf("DELETECOMMAND_APDU-1" to mapOf("apdu" to "00E40000")),
        // DeleteCommand(Password password, boolean dfSpecific)
        mapOf(
            "DELETECOMMAND_APDU-2" to mapOf("apdu-true" to "00E42089", "apdu-false" to "00E42009"),
        ),
        // DeleteCommand(byte[] reference) throws IOException
        mapOf("DELETECOMMAND_APDU-3" to mapOf("apdu" to "00E4210003830100")),
        // DeleteCommand(Key key, boolean dfSpecific)
        mapOf(
            "DELETECOMMAND_APDU-4" to mapOf("apdu-true" to "00E41081", "apdu-false" to "00E41001"),
        ),
        // ------------------------------------------------------------------------------------------------------------------------------------------
        // DeleteRecordCommand(ShortFileIdentifier sfi, int recordNumber)
        mapOf("DELETERECORDCOMMAND_APDU-1" to mapOf("apdu" to "800C0104")),
        // DeleteRecordCommand(int recordNumber)
        mapOf("DELETERECORDCOMMAND_APDU-2" to mapOf("apdu" to "800C01EC")),
        // ------------------------------------------------------------------------------------------------------------------------------------------
        // DisableVerificationRequirementCommand(Password password, boolean dfSpecific)
        mapOf(
            "DISABLEVERIFICATIONREQUIREMENTCOMMAND_APDU-1" to
                mapOf(
                    "apdu-true" to "002600810826123456FFFFFFFF",
                    "apdu-false" to "002600010826123456FFFFFFFF",
                ),
        ),
        // DisableVerificationRequirementCommand(Password password, boolean dfSpecific, Format2Pin verificationData)
        mapOf(
            "DISABLEVERIFICATIONREQUIREMENTCOMMAND_APDU-2" to
                mapOf("apdu-true" to "00260181", "apdu-false" to "00260101"),
        ),
        // ------------------------------------------------------------------------------------------------------------------------------------------
        // EnableVerificationRequirementCommand(Password password, boolean dfSpecifica)
        mapOf(
            "ENABLEVERIFICATIONREQUIREMENTCOMMAND_APDU-1" to
                mapOf(
                    "apdu-true" to "002800810826123456FFFFFFFF",
                    "apdu-false" to "002800010826123456FFFFFFFF",
                ),
        ),
        // EnableVerificationRequirementCommand(Password password, boolean dfSpecific, Format2Pin verificationData)
        mapOf(
            "ENABLEVERIFICATIONREQUIREMENTCOMMAND_APDU-2" to
                mapOf("apdu-true" to "00280181", "apdu-false" to "00280101"),
        ),
        // ------------------------------------------------------------------------------------------------------------------------------------------
        // EraseCommand
        mapOf("ERASECOMMAND_APDU-1" to mapOf("apdu" to "000E0000")),
        // EraseCommand(int offset)
        mapOf("ERASECOMMAND_APDU-2" to mapOf("apdu" to "000E0000")),
        // EraseCommand.EraseCommand(ShortFileIdentifier sfi)
        mapOf("ERASECOMMAND_APDU-3" to mapOf("apdu" to "000E9D00")),
        // EraseCommand.EraseCommand(ShortFileIdentifier sfi, int offset)
        mapOf("ERASECOMMAND_APDU-4" to mapOf("apdu" to "000E9D00")),
        // ------------------------------------------------------------------------------------------------------------------------------------------
        // EraseRecordCommand(int recordNumber)
        mapOf("ERASERECORDCOMMAND_APDU-1" to mapOf("apdu" to "000C0104")),
        // EraseRecordCommand(ShortFileIdentifier sfi, int recordNumber)
        mapOf("ERASERECORDCOMMAND_APDU-2" to mapOf("apdu" to "000C01EC")),
        // ------------------------------------------------------------------------------------------------------------------------------------------
        // ExternalMutualAuthenticateCommand(PsoAlgorithm psoAlgorithm, byte[] cmdData, boolean expectResponseData)
        mapOf(
            "EXTERNALMUTUALAUTHENTICATECOMMAND_APDU" to
                mapOf("apdu-true" to "00820000000001000000", "apdu-false" to "008200000100"),
        ),
        // ------------------------------------------------------------------------------------------------------------------------------------------
        // FingerprintCommand(@NotNull byte[] prefix)
        mapOf(
            "FINGERPRINTCOMMAND_APDU" to
                mapOf(
                    "apdu" to
                        "80FA0000000080000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F0000",
                ),
        ),
        // ------------------------------------------------------------------------------------------------------------------------------------------
        // GenerateAsymmetricKeyPairCommand$GakpUseCase,Key,boolean:
        mapOf(
            "GENERATEASYMMETRICKEYPAIRCOMMAND_APDU" to
                mapOf("apdu-true" to "0046C089000000", "apdu-false" to "0046C009000000"),
        ),
        // ------------------------------------------------------------------------------------------------------------------------------------------
        // GeneralAuthenticateCommand(boolean):
        mapOf(
            "GENERALAUTHENTICATECOMMAND_APDU-1" to
                mapOf("apdu-true" to "10860000027C0000", "apdu-false" to "00860000027C0000"),
        ),
        // ------------------------------------------------------------------------------------------------------------------------------------------
        // GeneralAuthenticateCommand(boolean, Pk1Pcd, 1)
        mapOf(
            "GENERALAUTHENTICATECOMMAND_APDU-2" to
                mapOf(
                    "apdu-true" to "10860000047C02810000",
                    "apdu-false" to "00860000047C02810000",
                ),
        ),
        // ------------------------------------------------------------------------------------------------------------------------------------------
        // GeneralAuthenticateCommand(boolean, Pk1Pcd, 3)
        mapOf(
            "GENERALAUTHENTICATECOMMAND_APDU-3" to
                mapOf(
                    "apdu-true" to "10860000047C02830000",
                    "apdu-false" to "00860000047C02830000",
                ),
        ),
        // ------------------------------------------------------------------------------------------------------------------------------------------
        // GeneralAuthenticateCommand(boolean, Pk1Pcd, 5)
        mapOf(
            "GENERALAUTHENTICATECOMMAND_APDU-4" to
                mapOf(
                    "apdu-true" to "10860000877C81848181",
                    "apdu-false" to "00860000877C81848181",
                ),
        ),
        // ------------------------------------------------------------------------------------------------------------------------------------------
        // GetChallengeCommand(int numberOfExpectedOctets)
        mapOf("GETCHALLENGECOMMAND_APDU" to mapOf("apdu" to "0084000008")),
        // ------------------------------------------------------------------------------------------------------------------------------------------
        // GetPinStatusCommand(Password password, boolean dfSpecific)
        mapOf(
            "GETPINSTATUSCOMMAND_APDU" to
                mapOf("apdu-true" to "80200081", "apdu-false" to "80200001"),
        ),
        // ------------------------------------------------------------------------------------------------------------------------------------------
        // GetRandomCommand(int numberOfExpectedOctetsInResponse)
        mapOf("GETRANDOMCOMMAND_APDU" to mapOf("apdu" to "8084000000")),
        // ------------------------------------------------------------------------------------------------------------------------------------------
        // InternalAuthenticateCommand(PsoAlgorithm psoAlgorithm, byte[] token)
        mapOf("INTERNALAUTHENTICATECOMMAND_APDU" to mapOf("apdu" to "00880000000001000000")),
        // ------------------------------------------------------------------------------------------------------------------------------------------
        // ListPublicKeyCommand
        mapOf("LISTPUBLICKEYCOMMAND_APDU" to mapOf("apdu" to "80CA0100000000")),
        // ------------------------------------------------------------------------------------------------------------------------------------------
        // LoadApplicationCommand(byte[] data, boolean commandChaining)
        mapOf(
            "LOADAPPLICATIONCOMMAND_APDU" to
                mapOf("apdu-true" to "10EA00000100", "apdu-false" to "00EA00000100"),
        ),
        // ------------------------------------------------------------------------------------------------------------------------------------------
        // ManageChannelCommand(boolean ifTrueOpenNewChannelElseResetOnApplicationLevel)
        mapOf(
            "MANAGECHANNELCOMMAND_APDU-1" to
                mapOf("apdu-true" to "0070000001", "apdu-false" to "00704001"),
        ),
        // ManageChannelCommand(int logicalChannelNumber, boolean ifTrueCloseChannelElseResetChannel)
        mapOf(
            "MANAGECHANNELCOMMAND_APDU-2" to
                mapOf("apdu-true" to "01708000", "apdu-false" to "01704000"),
        ),
        // ------------------------------------------------------------------------------------------------------------------------------------------
        // ManageSecurityEnvironmentCommand(int)
        mapOf("MANAGESECURITYENVIRONMENTCOMMAND_APDU-1" to mapOf("apdu" to "0022F301")),
        // ManageSecurityEnvironmentCommand(de.gematik.ti.healthcardaccess.commands.ManageSecurityEnvironmentCommand$MseUseCase,de.gematik.ti.healthcardaccess.cardobjects.Key,boolean,byte[])
        mapOf(
            "MANAGESECURITYENVIRONMENTCOMMAND_APDU-3" to
                mapOf(
                    "apdu-true" to "0022C1A406800100830189",
                    "apdu-false" to "0022C1A406800100830109",
                ),
        ),
        // ManageSecurityEnvironmentCommand$MseUseCase,de.gematik.ti.healthcardaccess.cardobjects.Key,boolean,byte[],int)
        mapOf(
            "MANAGESECURITYENVIRONMENTCOMMAND_APDU-4" to
                mapOf(
                    "apdu-true" to "0022C1A409800100830189840110",
                    "apdu-false" to "0022C1A409800100830109840110",
                ),
        ),
        // ManageSecurityEnvironmentCommand(de.gematik.ti.healthcardaccess.commands.ManageSecurityEnvironmentCommand$MseUseCase,de.gematik.ti.healthcardaccess.cardobjects.GemCvCertificate)
        mapOf(
            "MANAGESECURITYENVIRONMENTCOMMAND_APDU-5" to
                mapOf("apdu" to "002281B60A83084445475858830214"),
        ),
        // ManageSecurityEnvironmentCommand(de.gematik.ti.healthcardaccess.commands.ManageSecurityEnvironmentCommand$MseUseCase,de.gematik.ti.healthcardaccess.cardobjects.PsoAlgorithm,byte[])
        mapOf(
            "MANAGESECURITYENVIRONMENTCOMMAND_APDU-6" to mapOf("apdu" to "002281A406830100800105"),
        ),
        // ManageSecurityEnvironmentCommand(de.gematik.ti.healthcardaccess.cardobjects.PsoAlgorithm,byte[])
        mapOf(
            "MANAGESECURITYENVIRONMENTCOMMAND_APDU-7" to mapOf("apdu" to "002241A406830118800105"),
        ),
        // ------------------------------------------------------------------------------------------------------------------------------------------
        // PsoComputeCryptographicChecksum(de.gematik.ti.healthcardaccess.cardobjects.PsoAlgorithm,byte[])
        mapOf(
            "PSOCOMPUTECRYPTOGRAPHICCHECKSUM_APDU" to
                mapOf("apdu" to "002A8E8000000501090203040000"),
        ),
        // ------------------------------------------------------------------------------------------------------------------------------------------
        // PsoComputeCryptographicChecksum(de.gematik.ti.healthcardaccess.cardobjects.PsoAlgorithm,byte[])
        mapOf(
            "PSOVERIFYCRYPTPGRAPHICCHECKSUMCOMMAND_APDU" to
                mapOf("apdu" to "002A00A2108004090203048E083AE43D7CC33DD192"),
        ),
        // ------------------------------------------------------------------------------------------------------------------------------------------
        // PsoComputeDigitalSignatureCommand(de.gematik.ti.healthcardaccess.cardobjects.PsoAlgorithm,byte[])
        mapOf(
            "PSOCOMPUTEDIGITALSIGNATURECOMMAND_APDU-1" to
                mapOf(
                    "apdu" to
                        "002A9E9A0000206691A8D098B317D8AAE2256632F294A190F8C775334FC2B5001DE79856A11EF80000",
                ),
        ),
        mapOf(
            "PSOCOMPUTEDIGITALSIGNATURECOMMAND_APDU-2" to
                mapOf(
                    "apdu" to
                        "002A9E9A0000206691A8D098B317D8AAE2256632F294A190F8C775334FC2B5001DE79856A11EF80000",
                ),
        ),
        mapOf(
            "PSOCOMPUTEDIGITALSIGNATURECOMMAND_APDU-3" to
                mapOf(
                    "apdu" to
                        "002A9E9A0000333031300D0609608648016503040201050004206691A8D098B317D8AAE2256632F294A190F8C775334FC2B5001DE79856A11EF80000",
                ),
        ),
        mapOf(
            "PSOCOMPUTEDIGITALSIGNATURECOMMAND_APDU-4" to
                mapOf(
                    "apdu" to
                        "002A9E9A0000333031300D0609608648016503040201050004206691A8D098B317D8AAE2256632F294A190F8C775334FC2B5001DE79856A11EF80000",
                ),
        ),
        // ------------------------------------------------------------------------------------------------------------------------------------------
        // PsoDecipher(de.gematik.ti.healthcardaccess.cardobjects.PsoAlgorithm,byte[])
        mapOf("PSODECIPHER_APDU" to mapOf("apdu" to "002A808600000200000000")),
        // ------------------------------------------------------------------------------------------------------------------------------------------
        mapOf(
            "PSOENCIPHER_APDU-1" to
                mapOf(
                    "apdu" to
                        "002A868000011DA08201198001017F4982010A818201010094BEEBAA816749F9F304AC9EE7C70A13DCF6D2C9E511CEA7C07822CBAA21B713BB90DBDA98D9E12AA48076DC40B632EC9DFC9A8C5A7A51B92601D7A17D1FF1C8E164747CB1A95ABF14D8EA515B920167DFE2623580F43740A8109966A7CBFB663189F67EF3FDAA83075A67875C4D2715F38E0DE1270B05BD1F7BC192E9ABEF8938053481D9CA2612051822AB0AD1E61FF8E5423F4A8221BF0765C6658EC00B6A7F4E5A1FBC4F997E6FF35FD85BC2FBB5C797B63AF48194D31E4959F7651E8F5E1F1AF8819948DE2EA1123C5D9AD892B89E78BE63D582290BB548C4918E7B69F0784EAA4AE8706FFF643696E9F1FF9C01951E3BF318991611C77928066174E38182030100018005ABCE4412340000",
                ),
        ),
        mapOf(
            "PSOENCIPHER_APDU-2" to
                mapOf(
                    "apdu" to
                        "002A868000005DA05B80010B06092B24030302080101077F49438641047768387A5191CDF07F9BCCB0A627A889BB712CF5711A5932613AE693F52BB831368B1B6AD0EB5671FE1AF0BE188C2A05F7B09173791BC99F3A495933FFE08A348005ABCE4412340000",
                ),
        ),
        mapOf("PSOENCIPHER_APDU-3" to mapOf("apdu" to "002A8680000005ABCE4412340000")),
        mapOf(
            "PSOENCIPHER_APDU-4" to
                mapOf(
                    "apdu" to
                        "002A868000011DA08201198001057F4982010A818201010094BEEBAA816749F9F304AC9EE7C70A13DCF6D2C9E511CEA7C07822CBAA21B713BB90DBDA98D9E12AA48076DC40B632EC9DFC9A8C5A7A51B92601D7A17D1FF1C8E164747CB1A95ABF14D8EA515B920167DFE2623580F43740A8109966A7CBFB663189F67EF3FDAA83075A67875C4D2715F38E0DE1270B05BD1F7BC192E9ABEF8938053481D9CA2612051822AB0AD1E61FF8E5423F4A8221BF0765C6658EC00B6A7F4E5A1FBC4F997E6FF35FD85BC2FBB5C797B63AF48194D31E4959F7651E8F5E1F1AF8819948DE2EA1123C5D9AD892B89E78BE63D582290BB548C4918E7B69F0784EAA4AE8706FFF643696E9F1FF9C01951E3BF318991611C77928066174E38182030100018005ABCE4412340000",
                ),
        ),
        // ------------------------------------------------------------------------------------------------------------------------------------------
        // PsoVerifyDigitalSignatureCommand(java.security.interfaces.ECPublicKey,byte[],byte[])
        mapOf(
            "PSOVERIFYCERTIFICATECOMMAND_APDU" to
                mapOf(
                    "apdu" to
                        "002A00BEDC7F2181D87F4E81915F290170420844454758588302147F494D06082A8648CE3D04030286410472357CC3A35AB5CC4B17525D2A8270ED318E2697EAE30652D11DBAE26713F6B45ACF36A0D20A0EAEB569F09A5122C97080E78452FA82F8642CC7C6FDA97E545B5F200844454745581502147F4C1306082A8214004C048118530780FF7BDFF9FF0C5F25060104010102055F24060202010102045F37400FC9838053EA11D98AB2E4A7CA7D6D3641F5277C04BCF855AE04F56190F60B3E0F34DFF07B5AE1B985FEEAC082D5F483C54E43F768BDCA3EBEE0D59B6805829C",
                ),
        ),
        // ------------------------------------------------------------------------------------------------------------------------------------------
        // ECPublicKey,byte[],byte[]
        // hash:6691A8D098B317D8AAE2256632F294A190F8C775334FC2B5001DE79856A11EF8
        // signature:20B7D1F2D57E8A8DE38B50D651D3C9B60613831A622DBC4F171461014B60CEB42A317697EA02AFA66EBD61F4DB0BEF22ADC84A1302C49D683064995612328309
        mapOf(
            "PSOVERIFYDIGITALSIGNATURECOMMAND_APDU" to
                mapOf(
                    "apdu" to
                        "002A00A8B706092B240303020801010790206691A8D098B317D8AAE2256632F294A190F8C775334FC2B5001DE79856A11EF89C467F49438641047768387A5191CDF07F9BCCB0A627A889BB712CF5711A5932613AE693F52BB831368B1B6AD0EB5671FE1AF0BE188C2A05F7B09173791BC99F3A495933FFE08A349E4020B7D1F2D57E8A8DE38B50D651D3C9B60613831A622DBC4F171461014B60CEB42A317697EA02AFA66EBD61F4DB0BEF22ADC84A1302C49D683064995612328309",
                ),
        ),
        // ------------------------------------------------------------------------------------------------------------------------------------------
        mapOf("READCOMMAND_APDU-1" to mapOf("apdu" to "00B00000000000")),
        // ReadCommand(int,int)
        mapOf("READCOMMAND_APDU-2" to mapOf("apdu" to "00B0000000")),
        // ReadCommand(int)
        mapOf("READCOMMAND_APDU-3" to mapOf("apdu" to "00B00000000000")),
        // ReadCommand(de.gematik.ti.healthcardaccess.cardobjects.ShortFileIdentifier)
        mapOf("READCOMMAND_APDU-4" to mapOf("apdu" to "00B09D00000000")),
        // ReadCommand(de.gematik.ti.healthcardaccess.cardobjects.ShortFileIdentifier,int)
        mapOf("READCOMMAND_APDU-5" to mapOf("apdu" to "00B09D00000000")),
        // ReadCommand(de.gematik.ti.healthcardaccess.cardobjects.ShortFileIdentifier,int,int)
        mapOf("READCOMMAND_APDU-6" to mapOf("apdu" to "00B09D0000")),
        // ------------------------------------------------------------------------------------------------------------------------------------------
        // ReadRecordCommand(int)
        mapOf("READRECORDCOMMAND_APDU-1" to mapOf("apdu" to "00B20104000000")),
        // ReadRecordCommand(int,int)
        mapOf("READRECORDCOMMAND_APDU-2" to mapOf("apdu" to "00B2010400")),
        // ReadRecordCommand(de.gematik.ti.healthcardaccess.cardobjects.ShortFileIdentifier,int)
        mapOf("READRECORDCOMMAND_APDU-3" to mapOf("apdu" to "00B201EC000000")),
        // ReadRecordCommand(de.gematik.ti.healthcardaccess.cardobjects.ShortFileIdentifier,int,int)
        mapOf("READRECORDCOMMAND_APDU-4" to mapOf("apdu" to "00B201EC00")),
        // ------------------------------------------------------------------------------------------------------------------------------------------
        // SearchRecordCommand(int,byte[])
        mapOf("SEARCHRECORDCOMMAND_APDU-1" to mapOf("apdu" to "00A20104010000")),
        // SearchRecordCommand(int,byte[],int)
        mapOf("SEARCHRECORDCOMMAND_APDU-2" to mapOf("apdu" to "00A20104010000")),
        // SearchRecordCommand(de.gematik.ti.healthcardaccess.cardobjects.ShortFileIdentifier,int,byte[])
        mapOf("SEARCHRECORDCOMMAND_APDU-3" to mapOf("apdu" to "00A201EC010000")),
        // SearchRecordCommand(de.gematik.ti.healthcardaccess.cardobjects.ShortFileIdentifier,int,byte[],int)
        mapOf("SEARCHRECORDCOMMAND_APDU-4" to mapOf("apdu" to "00A201EC010000")),
        // ------------------------------------------------------------------------------------------------------------------------------------------
        // SelectCommand(boolean selectParentElseRoot, boolean readFirst)
        mapOf(
            "SELECTCOMMAND_APDU-1" to
                mapOf(
                    "apdu-false-false" to "00A4040C",
                    "apdu-true-false" to "00A4030C",
                    "apdu-false-true" to "00A40404000000",
                    "apdu-true-true" to "00A40304000000",
                ),
        ),
        // SelectCommand(ApplicationIdentifier aid)
        mapOf("SELECTCOMMAND_APDU-2" to mapOf("apdu" to "00A4040C06D27600000102")),
        // SelectCommand(FileIdentifier fid, boolean selectDfElseEf)
        mapOf(
            "SELECTCOMMAND_APDU-4" to
                mapOf("apdu-true" to "00A4010C022F01", "apdu-false" to "00A4020C022F01"),
        ),
        // SelectCommand(ApplicationIdentifier aid, boolean selectNextElseFirstOccurrence, boolean requestFcp, int fcpLength)
        mapOf(
            "SELECTCOMMAND_APDU-3" to
                mapOf(
                    "apdu-true-true" to "00A4040606D2760000010264",
                    "apdu-true-false" to "00A4040E06D27600000102",
                    "apdu-false-true" to "00A4040406D2760000010264",
                    "apdu-false-false" to "00A4040C06D27600000102",
                ),
        ),
        // SelectCommand(FileIdentifier fid, boolean selectNextElseFirstOccurrence, boolean requestFcp, int fcpLength)
        mapOf(
            "SELECTCOMMAND_APDU-5" to
                mapOf(
                    "apdu-true-true" to "00A40104022F0164",
                    "apdu-true-false" to "00A4010C022F01",
                    "apdu-false-true" to "00A40204022F0164",
                    "apdu-false-false" to "00A4020C022F01",
                ),
        ),
        // ------------------------------------------------------------------------------------------------------------------------------------------
        mapOf("SETLOGICALEOFCOMMAND_APDU-1" to mapOf("apdu" to "80E00000")),
        // (int)
        mapOf("SETLOGICALEOFCOMMAND_APDU-2" to mapOf("apdu" to "80E00000")),
        // ShortFileIdentifier
        mapOf("SETLOGICALEOFCOMMAND_APDU-3" to mapOf("apdu" to "80E09D00")),
        // ShortFileIdentifier,int
        mapOf("SETLOGICALEOFCOMMAND_APDU-4" to mapOf("apdu" to "80E09D00")),
        // ------------------------------------------------------------------------------------------------------------------------------------------
        // TerminateCardUsageCommand
        mapOf("TERMINATECARDUSAGECOMMAND_APDU" to mapOf("apdu" to "00FE0000")),
        // ------------------------------------------------------------------------------------------------------------------------------------------
        mapOf("TERMINATECOMMAND_APDU-1" to mapOf("apdu" to "00E80000")),
        // .Key,boolean)
        mapOf(
            "TERMINATECOMMAND_APDU-2" to
                mapOf("apdu-true" to "00E82089", "apdu-false" to "00E82009"),
        ),
        // byte[]
        mapOf("TERMINATECOMMAND_APDU-3" to mapOf("apdu" to "00E8210003830100")),
        // Password,boolean
        mapOf(
            "TERMINATECOMMAND_APDU-4" to
                mapOf("apdu-true" to "00E81081", "apdu-false" to "00E81001"),
        ),
        // ------------------------------------------------------------------------------------------------------------------------------------------
        // TerminateDfCommand
        mapOf("TERMINATEDFCOMMAND_APDU" to mapOf("apdu" to "00E60000")),
        // ------------------------------------------------------------------------------------------------------------------------------------------
        // UnlockEgkCommand(String unlockMethod, Password password, boolean dfSpecific, EncryptedPinFormat2 puk, EncryptedPinFormat2 newSecret)
        mapOf(
            "UNLOCKEGKCOMMAND_APDU-1" to
                mapOf(
                    "apdu-true" to "002C01810812345678FFFFFFFF",
                    "apdu-false" to "002C01010812345678FFFFFFFF",
                ),
        ),
        mapOf(
            "UNLOCKEGKCOMMAND_APDU-2" to
                mapOf(
                    "apdu-true" to "002C00811012345678FFFFFFFF87654321FFFFFFFF",
                    "apdu-false" to "002C00011012345678FFFFFFFF87654321FFFFFFFF",
                ),
        ),
        // UpdateCommand(byte[])
        mapOf("UPDATECOMMAND_APDU-1" to mapOf("apdu" to "00D600000100")),
        // UpdateCommand(int,byte[])
        mapOf("UPDATECOMMAND_APDU-2" to mapOf("apdu" to "00D600000100")),
        // UpdateCommand(de.gematik.ti.healthcardaccess.cardobjects.ShortFileIdentifier,byte[])
        mapOf("UPDATECOMMAND_APDU-3" to mapOf("apdu" to "00D69D000100")),
        // UpdateCommand(de.gematik.ti.healthcardaccess.cardobjects.ShortFileIdentifier,int,byte[])
        mapOf("UPDATECOMMAND_APDU-4" to mapOf("apdu" to "00D69D000100")),
        // ------------------------------------------------------------------------------------------------------------------------------------------
        // int,byte[]
        mapOf("UPDATERECORDCOMMAND_APDU-1" to mapOf("apdu" to "00DC01040100")),
        // ShortFileIdentifier,int,byte[]
        mapOf("UPDATERECORDCOMMAND_APDU-2" to mapOf("apdu" to "00DC01EC0100")),
        // ------------------------------------------------------------------------------------------------------------------------------------------
        // Password,boolean,Format2Pin
        mapOf(
            "VERITYPINCOMMAND_APDU" to
                mapOf(
                    "apdu-true" to "002000810826123456FFFFFFFF",
                    "apdu-false" to "002000010826123456FFFFFFFF",
                ),
        ),
        // ------------------------------------------------------------------------------------------------------------------------------------------
        // byte[]
        mapOf("WRITECOMMAND_APDU-1" to mapOf("apdu" to "00D000000100")),
        // ( ShortFileIdentifier,byte[]
        mapOf("WRITECOMMAND_APDU-2" to mapOf("apdu" to "00D09D000100")),
    )