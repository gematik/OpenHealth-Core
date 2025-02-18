/*
 * Copyright 2025 gematik GmbH
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

@file:Suppress("detekt.MaxLineLength")

package de.gematik.openhealth.smartcard.data

import de.gematik.openhealth.smartcard.hexSpaceFormat
import de.gematik.openhealth.smartcard.hexUppercaseFormat

fun getParameter(parameter: String): String =
    PARAMETERS
        .find { parameter in it }!!
        .getValue(parameter)
        .getValue("value")
        .hexToByteArray(hexUppercaseFormat)
        .toHexString(hexSpaceFormat)

private val PARAMETERS =
    listOf(
        // ShortFileIdentifier EF.ATR
        mapOf("PARAMETER_SID" to mapOf("value" to "1d")),
        // FileIdentifier
        mapOf("PARAMETER_FILEIDENTIFIER" to mapOf("value" to "2f01")),
        // ApplicationIdentifier DF.HCA
        mapOf("PARAMETER_APPLICATIONIDENTIFIER" to mapOf("value" to "d27600000102")),
        // EC
        mapOf(
            "PARAMETER_ECPUBLICKEY" to
                mapOf(
                    "value" to
                        "305A301406072A8648CE3D020106092B2403030208010107034200047768387A5191CDF07F9BCCB0A627A889BB712CF5711A5932613AE693F52BB831368B1B6AD0EB5671FE1AF0BE188C2A05F7B09173791BC99F3A495933FFE08A34",
                ),
        ),
        // CVC
        mapOf(
            "PARAMETER_GEMCVC" to
                mapOf(
                    "value" to
                        "7F2181D87F4E81915F290170420844454758588302147F494D06082A8648CE3D04030286410472357CC3A35AB5CC4B17525D2A8270ED318E2697EAE30652D11DBAE26713F6B45ACF36A0D20A0EAEB569F09A5122C97080E78452FA82F8642CC7C6FDA97E545B5F200844454745581502147F4C1306082A8214004C048118530780FF7BDFF9FF0C5F25060104010102055F24060202010102045F37400FC9838053EA11D98AB2E4A7CA7D6D3641F5277C04BCF855AE04F56190F60B3E0F34DFF07B5AE1B985FEEAC082D5F483C54E43F768BDCA3EBEE0D59B6805829C",
                ),
        ),
        // RSA
        mapOf(
            "PARAMETER_RSAPUBLICKEY" to
                mapOf(
                    "value" to
                        "30820122300D06092A864886F70D01010105000382010F003082010A028201010094BEEBAA816749F9F304AC9EE7C70A13DCF6D2C9E511CEA7C07822CBAA21B713BB90DBDA98D9E12AA48076DC40B632EC9DFC9A8C5A7A51B92601D7A17D1FF1C8E164747CB1A95ABF14D8EA515B920167DFE2623580F43740A8109966A7CBFB663189F67EF3FDAA83075A67875C4D2715F38E0DE1270B05BD1F7BC192E9ABEF8938053481D9CA2612051822AB0AD1E61FF8E5423F4A8221BF0765C6658EC00B6A7F4E5A1FBC4F997E6FF35FD85BC2FBB5C797B63AF48194D31E4959F7651E8F5E1F1AF8819948DE2EA1123C5D9AD892B89E78BE63D582290BB548C4918E7B69F0784EAA4AE8706FFF643696E9F1FF9C01951E3BF318991611C77928066174E3810203010001",
                ),
        ),
        // CHANNEL NUMBER
        mapOf("PARAMETER_INT_CHANNELNUMBER" to mapOf("value" to "1")),
        // RECORD NUMBER
        mapOf("PARAMETER_INT_RECORDNUMBER" to mapOf("value" to "1")),
        // FCP LENGTH
        mapOf("PARAMETER_INT_FCPLENGTH" to mapOf("value" to "100")),
        // NE
        mapOf("PARAMETER_INT_NE" to mapOf("value" to "0")),
        // GET RANDOM
        mapOf("PARAMETER_INT_GETRANDOM" to mapOf("value" to "0")),
        // GETCHALLENGE LENGTH
        mapOf("PARAMETER_INT_GETCHALLENGE_LENGTH" to mapOf("value" to "8")),
        // idDOMAIN
        mapOf("PARAMETER_INT_IDDOMAIN" to mapOf("value" to "16")),
        // OFFSET
        mapOf("PARAMETER_INT_OFFSET" to mapOf("value" to "0")),
        // OID
        mapOf("PARAMETER_BYTEARRAY_OID" to mapOf("value" to "00")),
        //
        mapOf("PARAMETER_BYTEARRAY_REFERENCE" to mapOf("value" to "00")),
        // Key REFERENCE
        mapOf("PARAMETER_BYTEARRAY_DEFAULT" to mapOf("value" to "00")),
        // cmdData INTERNL AUTH
        mapOf("PARAMETER_BYTEARRAY_INTERNLAUTH" to mapOf("value" to "00")),
        // cmdData EXTERNAL AUTH
        mapOf("PARAMETER_BYTEARRAY_EXTERNALAUTH" to mapOf("value" to "00")),
        // CMDDATA
        mapOf("PARAMETER_BYTEARRAY_CMDDATA" to mapOf("value" to "00")),
        // PACEINFO R1 GENERAL AUTH
        mapOf("PARAMETER_STRING_PACEINFOP256r1" to mapOf("value" to "BrainpoolP256r1")),
        // PACEINFO R2 GENERAL AUTH
        mapOf("PARAMETER_STRING_PACEINFOP384r1" to mapOf("value" to "BrainpoolP384r1")),
        // PACEINFO R3 GENERAL AUTH
        mapOf("PARAMETER_STRING_PACEINFOP512r1" to mapOf("value" to "BrainpoolP512r1")),
        // CAN GENERAL AUTH
        mapOf("PARAMETER_BYTEARRAY_CAN" to mapOf("value" to "313233343536")),
        // NonceZ GENERAL AUTH
        mapOf("PARAMETER_BYTEARRAY_NONZEZ" to mapOf("value" to "9E74C906558184C54ED910378EE4D33B")),
        // PK1 GENERAL AUTH
        mapOf(
            "PARAMETER_BYTEARRAY_PK1" to
                mapOf(
                    "value" to
                        "04250C92BB7F2B3EC607A855DEBBDCFC515C1563690068F78A854A3EB8D96B052D76D86245724F4EF3DF35DD3112AB37895C4A4A6FE8A0056CBA37BB6A51409A3D",
                ),
        ),
        // PK1PICC GENERAL AUTH
        mapOf(
            "PARAMETER_BYTEARRAY_PK1PICC" to
                mapOf(
                    "value" to
                        "044E2778F6AAEF54CB42865A3C30C753495AF4E53121400802D0AB1ACD665E9C774C2FAE1687E9DAA36C64570C909F93176F01EEAFCB45F9C08E49805F127D94EF",
                ),
        ),
        // PK2VP GENERAL AUTH
        mapOf(
            "PARAMETER_BYTEARRAY_PK2VP" to
                mapOf(
                    "value" to
                        "7C438341041B05278F276BD92E6B0EE3478BD3A93B03FE8E4C35556F0D6C13C89C504F91C065E85C1D289B306F61BE2CECCED4E7532BF0925A4907F246DF7A69C8D69ED24F",
                ),
        ),
        // PK2 GENERAL AUTH
        mapOf(
            "PARAMETER_BYTEARRAY_PK2" to
                mapOf(
                    "value" to
                        "041B05278F276BD92E6B0EE3478BD3A93B03FE8E4C35556F0D6C13C89C504F91C065E85C1D289B306F61BE2CECCED4E7532BF0925A4907F246DF7A69C8D69ED24F",
                ),
        ),
        // PK2PICC GENERAL AUTH
        mapOf(
            "PARAMETER_BYTEARRAY_PK2PICC" to
                mapOf(
                    "value" to
                        "041065EA94595ED0DF1BF450963CE84E0F7E0264279853D4E906EE21F1012F53843963AEB616CC7D468DCB731084657F80DD3555F539C10CC0FEC2E150E24B151B",
                ),
        ),
        // MACPCD GENERAL AUTH
        mapOf("PARAMETER_BYTEARRAY_MACPCD" to mapOf("value" to "151D6B331202A63E")),
        // MACPICC GENERAL AUTH
        mapOf("PARAMETER_BYTEARRAY_MACPICC" to mapOf("value" to "1B79EE1DF0BC3E3F")),
        // EC Curve PK1
        mapOf(
            "PARAMETER_STRING_ECCURVE_PK1" to
                mapOf(
                    "value" to
                        "(4e2778f6aaef54cb42865a3c30c753495af4e53121400802d0ab1acd665e9c77,4c2fae1687e9daa36c64570c909f93176f01eeafcb45f9c08e49805f127d94ef,1,7d5a0975fc2c3057eef67530417affe7fb8055c126dc5c6ce94a4b44f330b5d9)",
                ),
        ),
    )
