package de.gematik.openhealth.smartcard.model.command

import de.gematik.openhealth.smartcard.TestChannel
import de.gematik.openhealth.smartcard.card.EncryptedPinFormat2
import de.gematik.openhealth.smartcard.card.PasswordReference
import de.gematik.openhealth.smartcard.command.HealthCardCommand
import de.gematik.openhealth.smartcard.command.changeReferenceData
import de.gematik.openhealth.smartcard.data.getExpectedApdu
import de.gematik.openhealth.smartcard.hexSpaceFormat
import de.gematik.openhealth.smartcard.parameter
import de.gematik.openhealth.smartcard.runParametrizedTest
import kotlin.test.Test
import kotlin.test.assertEquals

class ChangeReferenceDataCommandTest {
    private val parameters = arrayOf(true, false)

    @Test
    fun shouldEqualChangeReferenceDataCommand1() =
        runParametrizedTest(*parameters) {
            val commandChaining = parameter<Boolean>()
            val expectedAPDU = getExpectedApdu("ChangeReferenceDataCommand_APDU-1", commandChaining)
            val command =
                HealthCardCommand.changeReferenceData(
                    passwordReference = PasswordReference(1),
                    dfSpecific = commandChaining,
                    oldSecret = EncryptedPinFormat2("123456"),
                    newSecret = EncryptedPinFormat2("012345"),
                )

            assertEquals(
                expectedAPDU,
                TestChannel().test(command).toHexString(hexSpaceFormat),
                message,
            )
        }

    @Test
    fun shouldEqualChangeReferenceDataCommand2() =
        runParametrizedTest(*parameters) {
            val commandChaining = parameter<Boolean>()
            val expectedAPDU = getExpectedApdu("ChangeReferenceDataCommand_APDU-2", commandChaining)
            val command =
                HealthCardCommand.changeReferenceData(
                    passwordReference = PasswordReference(2),
                    dfSpecific = commandChaining,
                    oldSecret = EncryptedPinFormat2("123456"),
                    newSecret = EncryptedPinFormat2("012345"),
                )

            assertEquals(
                expectedAPDU,
                TestChannel().test(command).toHexString(hexSpaceFormat),
                message,
            )
        }
}