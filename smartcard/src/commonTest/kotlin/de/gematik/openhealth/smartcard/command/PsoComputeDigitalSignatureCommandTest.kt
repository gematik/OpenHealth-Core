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

package de.gematik.openhealth.smartcard.command

import de.gematik.openhealth.smartcard.HealthCardTestScope
import de.gematik.openhealth.smartcard.command.HealthCardCommand
import de.gematik.openhealth.smartcard.command.psoComputeDigitalSignature
import de.gematik.openhealth.smartcard.data.getExpectedApdu
import de.gematik.openhealth.smartcard.hexSpaceFormat
import de.gematik.openhealth.smartcard.hexStringToByteArray
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals

class PsoComputeDigitalSignatureCommandTest {
    @Test
    fun shouldEqualPsoComputeDigitalSignatureCommand_Apdu1() =
        runTest {
            val expectedAPDU = getExpectedApdu("PSOCOMPUTEDIGITALSIGNATURECOMMAND_APDU-1")
            val dataToBeSigned =
                hexStringToByteArray(
                    "66 91 A8 D0 98 B3 17 D8 AA E2 25 66 32 F2 94 A1 90 " +
                        "F8 C7 75 33 4F C2 B5 00 1D E7 98 56 A1 1E F8",
                )

            val command = HealthCardCommand.psoComputeDigitalSignature(dataToBeSigned)

            assertEquals(
                expectedAPDU,
                HealthCardTestScope().test(command).toHexString(hexSpaceFormat),
            )
        }

    @Test
    fun shouldEqualPsoComputeDigitalSignatureCommand_Apdu2() =
        runTest {
            val expectedAPDU = getExpectedApdu("PSOCOMPUTEDIGITALSIGNATURECOMMAND_APDU-2")

            val dataToBeSigned =
                hexStringToByteArray(
                    "66 91 A8 D0 98 B3 17 D8 AA E2 25 66 32 F2 94 A1 90 " +
                        "F8 C7 75 33 4F C2 B5 00 1D E7 98 56 A1 1E F8",
                )

            val command = HealthCardCommand.psoComputeDigitalSignature(dataToBeSigned)

            assertEquals(
                expectedAPDU,
                HealthCardTestScope().test(command).toHexString(hexSpaceFormat),
            )
        }

    @Test
    fun shouldEqualPsoComputeDigitalSignatureCommand_Apdu3() =
        runTest {
            val expectedAPDU = getExpectedApdu("PSOCOMPUTEDIGITALSIGNATURECOMMAND_APDU-3")

            val dataToBeSigned =
                hexStringToByteArray(
                    "30 31 30 0D 06 09 60 86 48 01 65 03 04 02 01 05 " +
                        "00 04 20 66 91 A8 D0 98 B3 17 D8 AA E2 25 66 32 F2 " +
                        "94 A1 90 F8 C7 75 33 4F C2 B5 00 1D E7 98 56 A1 1E " +
                        "F8",
                )

            val command = HealthCardCommand.psoComputeDigitalSignature(dataToBeSigned)

            assertEquals(
                expectedAPDU,
                HealthCardTestScope().test(command).toHexString(hexSpaceFormat),
            )
        }

    @Test
    fun shouldEqualPsoComputeDigitalSignatureCommand_Apdu4() =
        runTest {
            val expectedAPDU = getExpectedApdu("PSOCOMPUTEDIGITALSIGNATURECOMMAND_APDU-4")

            val dataToBeSigned =
                hexStringToByteArray(
                    "30 31 30 0D 06 09 60 86 48 01 65 03 04 02 01 05 " +
                        "00 04 20 66 91 A8 D0 98 B3 17 D8 AA E2 25 66 32 F2 " +
                        "94 A1 90 F8 C7 75 33 4F C2 B5 00 1D E7 98 56 A1 1E " +
                        "F8",
                )

            val command = HealthCardCommand.psoComputeDigitalSignature(dataToBeSigned)

            assertEquals(
                expectedAPDU,
                HealthCardTestScope().test(command).toHexString(hexSpaceFormat),
            )
        }
}
