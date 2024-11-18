package de.gematik.kmp.crypto

import node.crypto.randomBytes

private class NodeSecureRandom : SecureRandom() {
    override fun nextBits(bitCount: Int): Int {
        val bytes = randomBytes(bitCount / 8 + 1).toByteArray()
        var result = 0
        for (i in bytes.indices) {
            result = result shl 8 or (bytes[i].toInt() and 0xFF)
        }
        return result ushr (bytes.size * 8 - bitCount)
    }
}

actual fun secureRandom(): SecureRandom = NodeSecureRandom()