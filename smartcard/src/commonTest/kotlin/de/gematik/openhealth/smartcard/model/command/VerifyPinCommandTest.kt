package de.gematik.openhealth.smartcard.model.command

import de.gematik.openhealth.smartcard.TestChannel
import de.gematik.openhealth.smartcard.card.EncryptedPinFormat2
import de.gematik.openhealth.smartcard.card.PasswordReference
import de.gematik.openhealth.smartcard.command.HealthCardCommand
import de.gematik.openhealth.smartcard.command.verifyPin
import de.gematik.openhealth.smartcard.data.getExpectedApdu
import de.gematik.openhealth.smartcard.hexSpaceFormat
import de.gematik.openhealth.smartcard.parameter
import de.gematik.openhealth.smartcard.runParametrizedTest
import kotlin.test.DefaultAsserter.assertEquals
import kotlin.test.Test

class VerifyPinCommandTest {
    private val parameters = arrayOf(true, false)

    @Test
    fun shouldEqualVerifyPinCommand() =
        runParametrizedTest(*parameters) {
            val dfSpecific = parameter<Boolean>()
            val passwordReference = PasswordReference(1)
            val pin = EncryptedPinFormat2("123456")
            val expectedAPDU = getExpectedApdu("VERITYPINCOMMAND_APDU", dfSpecific)
            val command = HealthCardCommand.verifyPin(passwordReference, dfSpecific, pin)

            assertEquals(
                expectedAPDU,
                TestChannel().test(command).toHexString(hexSpaceFormat),
                message,
            )
        }
}