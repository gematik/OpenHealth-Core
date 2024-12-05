/*
 * Copyright (c) 2024 gematik GmbH
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

package de.gematik.kmp.smartcard.model.command

import de.gematik.kmp.smartcard.TestChannel
import de.gematik.kmp.smartcard.data.getExpectedApdu
import de.gematik.kmp.smartcard.data.getParameter
import de.gematik.kmp.smartcard.hexSpaceFormat
import de.gematik.kmp.smartcard.card.CardKey
import de.gematik.kmp.smartcard.command.HealthCardCommand
import de.gematik.kmp.smartcard.command.manageSecEnvWithoutCurves
import de.gematik.kmp.smartcard.parameter
import de.gematik.kmp.smartcard.runParametrizedTest
import kotlin.test.Test
import kotlin.test.assertEquals

private const val ID_PRK_EGK_AUT_CVC_E256 = 9

private val KEY_PRK_EGK_AUT_CVC_E256 = CardKey(ID_PRK_EGK_AUT_CVC_E256)

class ManageSecurityEnvironmentCommandTest {
    private val parameters = arrayOf(true, false)

    @Test
    fun shouldEqualManageSecurityEnvironmentCommandMseUseCaseKeyBooleanOid() =
        runParametrizedTest(*parameters) {
            val dfSpecific = parameter<Boolean>()
            val expectedAPDU =
                getExpectedApdu("MANAGESECURITYENVIRONMENTCOMMAND_APDU-3", dfSpecific)
            val oid = getParameter("PARAMETER_BYTEARRAY_OID")
            val command =
                HealthCardCommand.manageSecEnvWithoutCurves(
                    KEY_PRK_EGK_AUT_CVC_E256,
                    dfSpecific,
                    oid.hexToByteArray(hexSpaceFormat),
                )

            assertEquals(expectedAPDU, TestChannel().test(command).toHexString(hexSpaceFormat))
        }
}