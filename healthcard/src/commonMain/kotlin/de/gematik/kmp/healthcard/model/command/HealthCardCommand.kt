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

import de.gematik.kmp.healthcard.model.card.ICardChannel

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
     * {@inheritDoc}
     *
     * @param iHealthCard
     * health card to execute the command
     *
     * @return result operation
     */
    suspend fun executeOn(channel: ICardChannel): HealthCardResponse {
        val cApdu = getCommandApdu(channel)
        return channel.transmit(cApdu).let {
            HealthCardResponse(expectedStatus[it.sw] ?: ResponseStatus.UNKNOWN_STATUS, it)
        }
    }

    private fun getCommandApdu(channel: ICardChannel): CardCommandApdu {
        val expectedLength =
            if (ne != null && ne == EXPECT_ALL_WILDCARD) {
                if (channel.isExtendedLengthSupported) {
                    NE_MAX_EXTENDED_LENGTH
                } else {
                    NE_MAX_SHORT_LENGTH
                }
            } else {
                ne
            }

        val cardCommandAPDU = CardCommandApdu.ofOptions(cla, ins, p1, p2, data, expectedLength)

        val apduLength = cardCommandAPDU.bytes.size
        require(apduLength <= channel.maxTransceiveLength) {
            "CommandApdu is too long to send. Limit for Reader is " + channel.maxTransceiveLength +
                " but length of commandApdu is " + apduLength
        }
        return cardCommandAPDU
    }

    // keep for extension functions
    companion object
}

class HealthCardResponse(
    val status: ResponseStatus,
    val apdu: CardResponseApdu,
)

suspend fun HealthCardCommand.executeSuccessfulOn(channel: ICardChannel): HealthCardResponse =
    this.executeOn(channel).also {
        it.requireSuccess()
    }

class ResponseException(
    val responseStatus: ResponseStatus,
) : Exception("$responseStatus")

fun HealthCardResponse.requireSuccess() {
    if (this.status != ResponseStatus.SUCCESS) {
        throw ResponseException(this.status)
    }
}