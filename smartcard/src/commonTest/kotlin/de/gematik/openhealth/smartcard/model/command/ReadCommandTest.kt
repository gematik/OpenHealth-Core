package de.gematik.openhealth.smartcard.model.command

import de.gematik.openhealth.smartcard.TestChannel
import de.gematik.openhealth.smartcard.command.HealthCardCommand
import de.gematik.openhealth.smartcard.command.read
import de.gematik.openhealth.smartcard.data.getExpectedApdu
import de.gematik.openhealth.smartcard.hexSpaceFormat
import de.gematik.openhealth.smartcard.identifier.ShortFileIdentifier
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals

class ReadCommandTest {
    @Test
    fun shouldEqualReadCommand_WithoutOffset() = runTest {
            val expectedAPDU = getExpectedApdu("READCOMMAND_APDU-1")
            val command = HealthCardCommand.read()

            assertEquals(
                expectedAPDU,
                TestChannel().test(command).toHexString(hexSpaceFormat),
            )
        }

    @Test
    fun shouldEqualReadCommand_WithOffset() {
        runTest {
            val expectedAPDU = getExpectedApdu("READCOMMAND_APDU-3")
            val command = HealthCardCommand.read(2)

            assertEquals(
                expectedAPDU,
                TestChannel().test(command).toHexString(hexSpaceFormat),
            )
        }
    }

    @Test
    fun shouldEqualReadCommand_WithOffsetAndNe() {
        runTest {
            val expectedAPDU = getExpectedApdu("READCOMMAND_APDU-2")
            val command = HealthCardCommand.read(2, 2)

            assertEquals(
                expectedAPDU,
                TestChannel().test(command).toHexString(hexSpaceFormat),
            )
        }
    }

    @Test
    fun shouldEqualReadCommand_WithSfi() {
        runTest {
            val expectedAPDU = getExpectedApdu("READCOMMAND_APDU-4")
            val sfi = ShortFileIdentifier(0x1D)
            val command = HealthCardCommand.read(sfi)

            assertEquals(
                expectedAPDU,
                TestChannel().test(command).toHexString(hexSpaceFormat),
            )
        }
    }

    @Test
    fun shouldEqualReadCommand_WithSfiAndOffset() {
        runTest {
            val expectedAPDU = getExpectedApdu("READCOMMAND_APDU-5")
            val sfi = ShortFileIdentifier(0x1D)
            val command = HealthCardCommand.read(sfi, 2)

            assertEquals(
                expectedAPDU,
                TestChannel().test(command).toHexString(hexSpaceFormat),
            )
        }
    }

    @Test
    fun shouldEqualReadCommand_WithSfiOffsetAndNe() {
        runTest {
            val expectedAPDU = getExpectedApdu("READCOMMAND_APDU-6")
            val sfi = ShortFileIdentifier(0x1D)
            val command = HealthCardCommand.read(sfi, 2, 2)

            assertEquals(
                expectedAPDU,
                TestChannel().test(command).toHexString(hexSpaceFormat),
            )
        }
    }
}