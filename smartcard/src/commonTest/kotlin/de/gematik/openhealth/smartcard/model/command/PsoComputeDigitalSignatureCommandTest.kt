package de.gematik.openhealth.smartcard.model.command

import de.gematik.openhealth.smartcard.TestChannel
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
    fun shouldEqualPsoComputeDigitalSignatureCommand_Apdu1() {
        runTest {
            val expectedAPDU = getExpectedApdu("PSOCOMPUTEDIGITALSIGNATURECOMMAND_APDU-1")
            val dataToBeSigned =
                hexStringToByteArray(
                    "66 91 A8 D0 98 B3 17 D8 AA E2 25 66 32 F2 94 A1 90 " +
                        "F8 C7 75 33 4F C2 B5 00 1D E7 98 56 A1 1E F8 00 00",
                )

            val command = HealthCardCommand.psoComputeDigitalSignature(dataToBeSigned)

            assertEquals(
                expectedAPDU,
                TestChannel().test(command).toHexString(hexSpaceFormat),
            )
        }
    }

    @Test
    fun shouldEqualPsoComputeDigitalSignatureCommand_Apdu2() {
        runTest {
            val expectedAPDU = getExpectedApdu("PSOCOMPUTEDIGITALSIGNATURECOMMAND_APDU-2")

            val dataToBeSigned =
                hexStringToByteArray(
                    "66 91 A8 D0 98 B3 17 D8 AA E2 25 66 32 F2 94 A1 90 " +
                        "F8 C7 75 33 4F C2 B5 00 1D E7 98 56 A1 1E F8 00 00",
                )

            val command = HealthCardCommand.psoComputeDigitalSignature(dataToBeSigned)

            assertEquals(
                expectedAPDU,
                TestChannel().test(command).toHexString(hexSpaceFormat),
            )
        }
    }

    @Test
    fun shouldEqualPsoComputeDigitalSignatureCommand_Apdu3() {
        runTest {
            val expectedAPDU = getExpectedApdu("PSOCOMPUTEDIGITALSIGNATURECOMMAND_APDU-3")

            val dataToBeSigned =
                hexStringToByteArray(
                    "30 31 30 0D 06 09 60 86 48 01 65 03 04 02 01 05 " +
                        "00 04 20 66 91 A8 D0 98 B3 17 D8 AA E2 25 66 32 F2 " +
                        "94 A1 90 F8 C7 75 33 4F C2 B5 00 1D E7 98 56 A1 1E " +
                        "F8 00 00",
                )

            val command = HealthCardCommand.psoComputeDigitalSignature(dataToBeSigned)

            assertEquals(
                expectedAPDU,
                TestChannel().test(command).toHexString(hexSpaceFormat),
            )
        }
    }

    @Test
    fun shouldEqualPsoComputeDigitalSignatureCommand_Apdu4() {
        runTest {
            val expectedAPDU = getExpectedApdu("PSOCOMPUTEDIGITALSIGNATURECOMMAND_APDU-4")

            val dataToBeSigned =
                hexStringToByteArray(
                    "30 31 30 0D 06 09 60 86 48 01 65 03 04 02 01 05 " +
                        "00 04 20 66 91 A8 D0 98 B3 17 D8 AA E2 25 66 32 F2 " +
                        "94 A1 90 F8 C7 75 33 4F C2 B5 00 1D E7 98 56 A1 1E " +
                        "F8 00 00",
                )

            val command = HealthCardCommand.psoComputeDigitalSignature(dataToBeSigned)

            assertEquals(
                expectedAPDU,
                TestChannel().test(command).toHexString(hexSpaceFormat),
            )
        }
    }
}