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

package de.gematik.openhealth.smartcard.command

import de.gematik.openhealth.smartcard.command.CardCommandApdu.Companion.ofOptions

private const val HEX_FF = 0xff

const val NE_MAX_EXTENDED_LENGTH = 65536
const val NE_MAX_SHORT_LENGTH = 256
const val EXPECT_ALL_WILDCARD = -1

/**
 * Superclass for all health card commands.
 */
class HealthCardCommand(
    val expectedStatus: Map<Int, HealthCardResponseStatus>,
    val cla: Int,
    val ins: Int,
    val p1: Int = 0,
    val p2: Int = 0,
    val data: ByteArray? = null,
    val ne: Int? = null,
) {
    init {
        require(!(cla > HEX_FF || ins > HEX_FF || p1 > HEX_FF || p2 > HEX_FF)) {
            "Parameter value exceeds one byte"
        }
    }

    // Keep for extension functions
    companion object
}

fun HealthCardCommand.commandApdu(scopeSupportsExtendedLength: Boolean): CardCommandApdu {
    val expectedLength =
        if (ne != null && ne == EXPECT_ALL_WILDCARD) {
            if (scopeSupportsExtendedLength) {
                NE_MAX_EXTENDED_LENGTH
            } else {
                NE_MAX_SHORT_LENGTH
            }
        } else {
            ne
        }

    return ofOptions(cla, ins, p1, p2, data, expectedLength)
}

/**
 * Represents the response from a HealthCardCommand.
 *
 * @property status The [HealthCardResponseStatus] of the command execution.
 * @property apdu The raw [CardResponseApdu] received from the card.
 */
class HealthCardResponse(
    val status: HealthCardResponseStatus,
    val apdu: CardResponseApdu,
)

/**
 * Exception thrown when a command execution was not successful.
 *
 * @property healthCardResponseStatus The [HealthCardResponseStatus] indicating the reason for the failure.
 */
class ResponseException(
    val healthCardResponseStatus: HealthCardResponseStatus,
) : Exception("$healthCardResponseStatus")

/**
 * Checks if the command execution was successful and throws a [ResponseException] if not.
 *
 * @throws ResponseException if the command was not successful.
 */
fun HealthCardResponse.requireSuccess() {
    if (this.status != HealthCardResponseStatus.SUCCESS) {
        throw ResponseException(this.status)
    }
}
