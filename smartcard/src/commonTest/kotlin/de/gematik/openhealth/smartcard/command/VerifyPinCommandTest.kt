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
import de.gematik.openhealth.smartcard.card.EncryptedPinFormat2
import de.gematik.openhealth.smartcard.card.PasswordReference
import de.gematik.openhealth.smartcard.command.HealthCardCommand
import de.gematik.openhealth.smartcard.command.verifyPin
import de.gematik.openhealth.smartcard.data.getExpectedApdu
import de.gematik.openhealth.smartcard.hexSpaceFormat
import de.gematik.openhealth.smartcard.parameter
import de.gematik.openhealth.smartcard.runParametrizedTest
import kotlin.test.Test
import kotlin.test.assertEquals

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
                HealthCardTestScope().test(command).toHexString(hexSpaceFormat),
                message,
            )
        }
}
