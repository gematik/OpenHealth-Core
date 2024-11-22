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

package de.gematik.kmp.healthcard.model.command

import de.gematik.kmp.healthcard.TestChannel
import de.gematik.kmp.healthcard.data.getExpectedApdu
import de.gematik.kmp.healthcard.hexSpaceFormat
import de.gematik.kmp.healthcard.parameter
import de.gematik.kmp.healthcard.runParametrizedTest
import kotlin.test.Test
import kotlin.test.assertEquals

class GeneralAuthenticateCommandTest {
    private val parameters = arrayOf(true, false)

    @Test
    fun shouldEqualGeneralAuthenticateCommand1() = runParametrizedTest(*parameters) {
        val commandChaining = parameter<Boolean>()
        val expectedAPDU = getExpectedApdu("GENERALAUTHENTICATECOMMAND_APDU-1", commandChaining)
        val command = HealthCardCommand.generalAuthenticate(commandChaining)

        assertEquals(expectedAPDU, TestChannel().test(command).toHexString(hexSpaceFormat), message)
    }

    @Test
    fun shouldEqualGeneralAuthenticateCommand2() = runParametrizedTest(*parameters) {
        val commandChaining = parameter<Boolean>()
        val expectedAPDU = getExpectedApdu("GENERALAUTHENTICATECOMMAND_APDU-2", commandChaining)
        val command = HealthCardCommand.generalAuthenticate(commandChaining, byteArrayOf(), 1)

        assertEquals(expectedAPDU, TestChannel().test(command).toHexString(hexSpaceFormat), message)
    }

    @Test
    fun shouldEqualGeneralAuthenticateCommand3() = runParametrizedTest(*parameters) {
        val commandChaining = parameter<Boolean>()
        val expectedAPDU = getExpectedApdu("GENERALAUTHENTICATECOMMAND_APDU-3", commandChaining)
        val command = HealthCardCommand.generalAuthenticate(commandChaining, byteArrayOf(), 3)

        assertEquals(expectedAPDU, TestChannel().test(command).toHexString(hexSpaceFormat), message)
    }
}
