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

package de.gematik.openhealth.smartcard.command

import de.gematik.openhealth.smartcard.card.SmartCard
import de.gematik.openhealth.smartcard.command.CardCommandApdu.Companion.ofOptions

private const val HEX_FF = 0xff

const val NE_MAX_EXTENDED_LENGTH = 65536
const val NE_MAX_SHORT_LENGTH = 256
const val EXPECT_ALL_WILDCARD = -1

/**
 * Superclass for all HealthCardCommands
 */
class HealthCardCommand(
    val expectedStatus: Map<Int, ResponseStatus>,
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

    /**
     * Executes the command on the given [SmartCard.CommunicationScope].
     *
     * @param scope The communication scope to execute the command on.
     * @return The [HealthCardResponse] received from the card.
     */
    fun executeOn(scope: SmartCard.CommunicationScope): HealthCardResponse {
        val cApdu = getCommandApdu(scope)
        return scope.transmit(cApdu).let {
            HealthCardResponse(expectedStatus[it.sw] ?: ResponseStatus.UNKNOWN_STATUS, it)
        }
    }

    private fun getCommandApdu(scope: SmartCard.CommunicationScope): CardCommandApdu {
        val expectedLength =
            if (ne != null && ne == EXPECT_ALL_WILDCARD) {
                if (scope.supportsExtendedLength) {
                    NE_MAX_EXTENDED_LENGTH
                } else {
                    NE_MAX_SHORT_LENGTH
                }
            } else {
                ne
            }

        val cardCommandAPDU = ofOptions(cla, ins, p1, p2, data, expectedLength)

        // No need to check apdu length here, because we do not have the maxTransceiveLength anymore.
        // The underlying implementation of the SmartCard.CommunicationScope.transmit() method
        // should handle this.

        return cardCommandAPDU
    }

    // keep for extension functions
    companion object
}

/**
 * Represents the response from a HealthCardCommand.
 *
 * @property status The [ResponseStatus] of the command execution.
 * @property apdu The raw [CardResponseApdu] received from the card.
 */
class HealthCardResponse(
    val status: ResponseStatus,
    val apdu: CardResponseApdu,
)

/**
 * Executes the command on the given [SmartCard.CommunicationScope] and throws a [ResponseException]
 * if the command was not successful.
 *
 * @param scope The communication scope to execute the command on.
 * @return The [HealthCardResponse] received from the card.
 * @throws ResponseException if the command was not successful.
 */
fun HealthCardCommand.executeSuccessfulOn(scope: SmartCard.CommunicationScope): HealthCardResponse =
    this.executeOn(scope).also {
        it.requireSuccess()
    }

/**
 * Exception thrown when a command execution was not successful.
 *
 * @property responseStatus The [ResponseStatus] indicating the reason for the failure.
 */
class ResponseException(
    val responseStatus: ResponseStatus,
) : Exception("$responseStatus")

/**
 * Checks if the command execution was successful and throws a [ResponseException] if not.
 *
 * @throws ResponseException if the command was not successful.
 */
fun HealthCardResponse.requireSuccess() {
    if (this.status != ResponseStatus.SUCCESS) {
        throw ResponseException(this.status)
    }
}