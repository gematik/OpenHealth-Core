/*
 * Copyright (c) 2025 gematik GmbH
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

package de.gematik.openhealth.smartcard.model.command

import de.gematik.openhealth.smartcard.HealthCardTestScope
import de.gematik.openhealth.smartcard.card.EncryptedPinFormat2
import de.gematik.openhealth.smartcard.card.PasswordReference
import de.gematik.openhealth.smartcard.command.HealthCardCommand
import de.gematik.openhealth.smartcard.command.UnlockMethod
import de.gematik.openhealth.smartcard.command.unlockEgk
import de.gematik.openhealth.smartcard.data.getExpectedApdu
import de.gematik.openhealth.smartcard.hexSpaceFormat
import de.gematik.openhealth.smartcard.parameter
import de.gematik.openhealth.smartcard.runParametrizedTest
import kotlin.test.DefaultAsserter.assertEquals
import kotlin.test.Test

class UnlockEgkCommandTest {
    private val parameters = arrayOf(true, false)

    @Test
    fun shouldEqualUnlockEgkCommandWithoutNewSecret() =
        runParametrizedTest(*parameters) {
            val dfSpecific = parameter<Boolean>()
            val unlockMethod =
                UnlockMethod.ResetRetryCounter.name
            val passwordReference = PasswordReference(1)
            val puk = EncryptedPinFormat2("12345678")
            val newSecret: EncryptedPinFormat2? = null
            val expectedAPDU =
                getExpectedApdu(
                    "UNLOCKEGKCOMMAND_APDU-1",
                    dfSpecific,
                )
            val command =
                HealthCardCommand.unlockEgk(
                    unlockMethod,
                    passwordReference,
                    dfSpecific,
                    puk,
                    newSecret,
                )

            assertEquals(
                expectedAPDU,
                HealthCardTestScope().test(command).toHexString(hexSpaceFormat),
                message,
            )
        }

    @Test
    fun shouldEqualUnlockEgkCommandWithNewSecret() =
        runParametrizedTest(*parameters) {
            val dfSpecific = parameter<Boolean>()
            val unlockMethod = UnlockMethod.ResetRetryCounterWithNewSecret.name
            val passwordReference = PasswordReference(1)
            val puk = EncryptedPinFormat2("12345678")
            val newSecret = EncryptedPinFormat2("87654321")
            val expectedAPDU = getExpectedApdu("UNLOCKEGKCOMMAND_APDU-2", dfSpecific)
            val command =
                HealthCardCommand.unlockEgk(
                    unlockMethod,
                    passwordReference,
                    dfSpecific,
                    puk,
                    newSecret,
                )

            assertEquals(
                expectedAPDU,
                HealthCardTestScope().test(command).toHexString(hexSpaceFormat),
                message,
            )
        }
}