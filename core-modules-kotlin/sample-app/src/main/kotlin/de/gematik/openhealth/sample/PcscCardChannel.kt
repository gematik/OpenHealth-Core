package de.gematik.openhealth.sample

import de.gematik.openhealth.healthcard.CardChannel
import de.gematik.openhealth.healthcard.CardChannelException
import de.gematik.openhealth.healthcard.TrustedChannelException
import javax.smartcardio.CardChannel as PcscChannel
import javax.smartcardio.CardException
import javax.smartcardio.CommandAPDU

/**
 * Adapts the javax.smartcardio channel so it can be consumed by the UniFFI generated API.
 */
class PcscCardChannel(
    private val delegate: PcscChannel,
) : CardChannel {

    override fun supportsExtendedLength(): Boolean {
        val historicalBytes = delegate.card.atr.historicalBytes
        return historicalBytes != null && historicalBytes.size > 15
    }

    override fun transmit(command: ByteArray): ByteArray {
        try {
            val response = delegate.transmit(CommandAPDU(command))
            return response.bytes
        } catch (ex: CardException) {
            throw CardChannelException.Transport(
                TrustedChannelException.Transport(
                    code = 0u,
                    reason = ex.message ?: "PC/SC transmit failed",
                )
            )
        }
    }
}
