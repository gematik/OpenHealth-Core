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

package de.gematik.openhealth.smartcard.model.command

import de.gematik.openhealth.smartcard.HealthCardTestScope
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
                HealthCardTestScope().test(command).toHexString(hexSpaceFormat),
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
                HealthCardTestScope().test(command).toHexString(hexSpaceFormat),
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
                HealthCardTestScope().test(command).toHexString(hexSpaceFormat),
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
                HealthCardTestScope().test(command).toHexString(hexSpaceFormat),
            )
        }
    }
}
