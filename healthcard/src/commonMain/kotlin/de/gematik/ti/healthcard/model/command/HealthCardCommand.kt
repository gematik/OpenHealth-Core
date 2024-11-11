/*
 * ${GEMATIK_COPYRIGHT_STATEMENT}
 */

package de.gematik.ti.healthcard.model.command

import de.gematik.ti.healthcard.model.card.ICardChannel

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
    val ne: Int? = null
) {
    init {
        require(!(cla > HEX_FF || ins > HEX_FF || p1 > HEX_FF || p2 > HEX_FF)) { "Parameter value exceeds one byte" }
    }

    /**
     * {@inheritDoc}
     *
     * @param iHealthCard
     * health card to execute the command
     *
     * @return result operation
     */
    fun executeOn(channel: ICardChannel): HealthCardResponse {
        val cApdu = getCommandApdu(channel)
        return channel.transmit(cApdu).let {
            HealthCardResponse(expectedStatus[it.sw] ?: ResponseStatus.UNKNOWN_STATUS, it)
        }
    }

    private fun getCommandApdu(channel: ICardChannel): CommandApdu {
        val expectedLength = if (ne != null && ne == EXPECT_ALL_WILDCARD) {
            if (channel.isExtendedLengthSupported) {
                NE_MAX_EXTENDED_LENGTH
            } else {
                NE_MAX_SHORT_LENGTH
            }
        } else {
            ne
        }

        val commandAPDU = CommandApdu.ofOptions(cla, ins, p1, p2, data, expectedLength)

        val apduLength = commandAPDU.bytes.size
        require(apduLength <= channel.maxTransceiveLength) {
            "CommandApdu is too long to send. Limit for Reader is " + channel.maxTransceiveLength +
                " but length of commandApdu is " + apduLength
        }
        return commandAPDU
    }

    // keep for extension functions
    companion object
}

class HealthCardResponse(val status: ResponseStatus, val apdu: ResponseApdu)

fun HealthCardCommand.executeSuccessfulOn(channel: ICardChannel): HealthCardResponse =
    this.executeOn(channel).also {
        it.requireSuccess()
    }

class ResponseException(val responseStatus: ResponseStatus) : Exception()

fun HealthCardResponse.requireSuccess() {
    if (this.status != ResponseStatus.SUCCESS) {
        throw ResponseException(this.status)
    }
}
