// SPDX-FileCopyrightText: Copyright 2026 gematik GmbH
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

package de.gematik.openhealth.healthcard

import java.util.HexFormat
import kotlin.test.Test
import kotlin.test.assertEquals

class HealthCardCommandCompatTest {

    private val hex = HexFormat.of()

    @Test
    fun reproducesLegacyPoppApdus() {
        assertEquals(
            "00a4040c07d2760001448000",
            toHex(HealthCardCommand.selectAid(hex.parseHex("D2760001448000")), false),
        )
        assertEquals("00b0910000", toHex(HealthCardCommand.readSfi(0x11), false))
        assertEquals("00b08400000000", toHex(HealthCardCommand.readSfi(0x04), true))
        assertEquals("80ca0100000000", toHex(HealthCardCommand.listPublicKeys(), true))
        assertEquals(
            "002241a406840109800154",
            toHex(HealthCardCommand.manageSecEnvSelectPrivateKey(0x09, 0x54), false),
        )
        assertEquals(
            "002281b60a83084445475858870222",
            toHex(
                HealthCardCommand.manageSecEnvSetSignatureKeyReference(hex.parseHex("4445475858870222")),
                false,
            ),
        )
        assertEquals(
            "002a00be03010203",
            toHex(HealthCardCommand.psoComputeDigitalSignatureCvc(hex.parseHex("010203")), false),
        )
        assertEquals(
            "10860000107c0ec30c000a8027600101169990210100",
            toHex(
                HealthCardCommand.generalAuthenticateMutualAuthenticationStep1(
                    hex.parseHex("000a80276001011699902101"),
                ),
                false,
            ),
        )
        assertEquals(
            "00860000457c438541040102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40",
            toHex(
                HealthCardCommand.generalAuthenticateElcStep2(
                    byteArrayOf(
                        0x04.toByte(),
                        *ByteArray(64) { index -> (index + 1).toByte() },
                    ),
                ),
                false,
            ),
        )
        assertEquals(
            "0088000018000102030405060708090a0b0c0d0e0f101112131415161700",
            toHex(
                HealthCardCommand.internalAuthenticate(
                    hex.parseHex("000102030405060708090a0b0c0d0e0f1011121314151617"),
                ),
                false,
            ),
        )
    }

    private fun toHex(command: HealthCardCommand, supportsExtendedLength: Boolean): String =
        hex.formatHex(command.toApdu(supportsExtendedLength).toVec().cloneAsNonzeroizingVec())
}
