package de.gematik.openhealth.smartcard.model.command

import de.gematik.openhealth.smartcard.TestChannel
import de.gematik.openhealth.smartcard.card.PasswordReference
import de.gematik.openhealth.smartcard.command.HealthCardCommand
import de.gematik.openhealth.smartcard.command.getPinStatus
import de.gematik.openhealth.smartcard.data.getExpectedApdu
import de.gematik.openhealth.smartcard.hexSpaceFormat
import de.gematik.openhealth.smartcard.parameter
import de.gematik.openhealth.smartcard.runParametrizedTest
import kotlin.test.DefaultAsserter.assertEquals
import kotlin.test.Test

class GetPinStatusCommandTest {
    private val parameters = arrayOf(true, false)

    @Test
    fun shouldEqualGetPinStatusCommand() =
        runParametrizedTest(*parameters) {
            val dfSpecific = parameter<Boolean>()
            val password = PasswordReference(1)
            val expectedAPDU = getExpectedApdu("GETPINSTATUSCOMMAND_APDU", dfSpecific)
            val command = HealthCardCommand.getPinStatus(password, dfSpecific)

            assertEquals(
                expectedAPDU,
                TestChannel().test(command).toHexString(hexSpaceFormat),
                message,
            )
        }
}