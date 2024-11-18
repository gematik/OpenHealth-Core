

package de.gematik.ti.healthcard.model.card

/**
 * Pace Key for TrustedChannel with Session key for encoding and Session key for message authentication
 */
data class PaceKey(
    val enc: ByteArray,
    val mac: ByteArray,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as PaceKey

        if (!enc.contentEquals(other.enc)) return false
        if (!mac.contentEquals(other.mac)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = enc.contentHashCode()
        result = 31 * result + mac.contentHashCode()
        return result
    }
}