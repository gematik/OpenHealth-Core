package de.gematik.openhealth.smartcard.model.command

import de.gematik.openhealth.smartcard.TestChannel
import de.gematik.openhealth.smartcard.command.HealthCardCommand
import de.gematik.openhealth.smartcard.command.getRandomValues
import de.gematik.openhealth.smartcard.data.getExpectedApdu
import de.gematik.openhealth.smartcard.hexSpaceFormat
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals

class GetRandomValuesCommandTest {
    @Test
    fun shouldEqualGetRandomValuesCommand_WithLength0() {
        runTest {
            val expectedAPDU =
                getExpectedApdu("GETRANDOMCOMMAND_APDU-1")
            val length = 0

            val command = HealthCardCommand.getRandomValues(length)

            assertEquals(
                expectedAPDU,
                TestChannel().test(command).toHexString(hexSpaceFormat),
            )
        }
    }

    @Test
    fun shouldEqualGetRandomValuesCommand_WithLengthEight() {
        runTest {
            val expectedAPDU =
                getExpectedApdu("GETRANDOMCOMMAND_APDU-2")
            val length = 8

            val command = HealthCardCommand.getRandomValues(length)

            assertEquals(
                expectedAPDU,
                TestChannel().test(command).toHexString(hexSpaceFormat),
            )
        }
    }

    @Test
    fun shouldEqualGetRandomValuesCommand_WithLength16() {
        runTest {
            val expectedAPDU =
                getExpectedApdu("GETRANDOMCOMMAND_APDU-3")
            val length = 16

            val command = HealthCardCommand.getRandomValues(length)

            assertEquals(
                expectedAPDU,
                TestChannel().test(command).toHexString(hexSpaceFormat),
            )
        }
    }

    @Test
    fun shouldEqualGetRandomValuesCommand_WithLength32() {
        runTest {
            val expectedAPDU =
                getExpectedApdu("GETRANDOMCOMMAND_APDU-4")
            val length = 32

            val command = HealthCardCommand.getRandomValues(length)

            assertEquals(
                expectedAPDU,
                TestChannel().test(command).toHexString(hexSpaceFormat),
            )
        }
    }
}