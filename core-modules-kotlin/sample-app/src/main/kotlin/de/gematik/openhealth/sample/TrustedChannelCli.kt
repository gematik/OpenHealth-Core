package de.gematik.openhealth.sample

import de.gematik.openhealth.healthcard.TrustedChannelFactory
import javax.smartcardio.Card
import javax.smartcardio.CardTerminals
import javax.smartcardio.TerminalFactory

/**
 * Minimal demonstration that wires the trusted channel implementation into the PC/SC stack.
 *
 * You need to provide the card access number via the `CARD_ACCESS_NUMBER` environment variable
 * (or the `-DcardAccessNumber=...` JVM property). The optional `-DsampleApdu=00A4040000...`
 * property can be used to send a different APDU.
 */
fun main() {
    val cardAccessNumber = System.getProperty("cardAccessNumber")
        ?: System.getenv("CARD_ACCESS_NUMBER")
        ?: error("Provide CARD_ACCESS_NUMBER env variable or -DcardAccessNumber=XXXXXX")
    val apdu = System.getProperty("sampleApdu")
        ?.takeIf { it.isNotBlank() }
        ?.let(::hexToBytes)
        ?: byteArrayOf(0x00, 0x84.toByte(), 0x00, 0x00, 0x08) // GET CHALLENGE default

    val card = openPcscCard()
    try {
        val trustedChannel = PcscCardChannel(card.basicChannel).let { channel ->
            TrustedChannelFactory.establish(channel, cardAccessNumber)
        }
        println("Trusted channel established.")
        val response = trustedChannel.transmit(apdu)
        println("Trusted channel response: ${response.toHexString()}")
    } finally {
        try {
            card.disconnect(false)
        } catch (_: Exception) {
            // Ignore disconnect errors
        }
    }
}

private fun openPcscCard(): Card {
    val factory = TerminalFactory.getDefault()
    val terminals: CardTerminals = factory.terminals()
    val available = terminals.list().ifEmpty {
        error("No connected smart-card terminals found.")
    }
    val index = System.getProperty("pcsc.terminal")?.toIntOrNull() ?: 0
    require(index in available.indices) {
        "Terminal index $index is out of bounds. Available terminals: ${available.map { it.name }}"
    }
    val terminal = available[index]
    println("Using terminal '${terminal.name}' to open a card session.")
    return terminal.connect("*")
}

private fun ByteArray.toHexString(): String =
    joinToString(separator = " ") { eachByte -> "%02X".format(eachByte) }

private fun hexToBytes(value: String): ByteArray {
    val sanitized = value.replace("\\s".toRegex(), "")
    require(sanitized.length % 2 == 0) { "Hex string must have an even length." }
    return sanitized.chunked(2)
        .map { chunk -> chunk.toInt(16).toByte() }
        .toByteArray()
}
