/*
 * ${GEMATIK_COPYRIGHT_STATEMENT}
 */

package de.gematik.ti.healthcard.utils


object Bytes {
    private const val PAD = 0x80.toByte()

    /**
     * Padding the data with [PAD].
     *
     * @param data byte array with data
     * @param blockSize int
     * @return byte array with padded data
     */
    fun padData(data: ByteArray, blockSize: Int): ByteArray =
        ByteArray(data.size + (blockSize - data.size % blockSize)).apply {
            data.copyInto(this)
            this[data.size] = PAD
        }

    /**
     * Unpadding the data.
     *
     * @param paddedData byte array with padded data
     * @return byte array with data
     */
    fun unPadData(paddedData: ByteArray): ByteArray {
        for (i in paddedData.indices.reversed()) {
            if (paddedData[i] == PAD) {
                return paddedData.copyOfRange(0, i)
            }
        }
        return paddedData
    }

    /**
     * Converts a BigInteger into a ByteArray. A leading byte with the value 0 is truncated.
     *
     * @param bigInteger The BigInteger object to convert.
     * @return The ByteArray without leading 0-byte
     */
    fun bigIntToByteArray(bigInteger: BigInteger): ByteArray {
        val bigIntArray = bigInteger.toByteArray()
        return if (bigIntArray[0] == 0.toByte()) {
            bigIntArray.copyOfRange(1, bigIntArray.size)
        } else {
            bigIntArray
        }
    }
}
