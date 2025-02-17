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

@file:Suppress("MagicNumber")

package de.gematik.openhealth.smartcard.command

/**
 * Value for when a wildcard for the expected length encoding is needed for extended length APDUs.
 * This value (65536) indicates that the maximum possible length is expected.
 */
const val EXPECTED_LENGTH_WILDCARD_EXTENDED: Int = 65536

/**
 * Value for when a wildcard for the expected length encoding is needed for short length APDUs.
 * This value (256) indicates that the maximum possible length is expected for short APDUs.
 */
const val EXPECTED_LENGTH_WILDCARD_SHORT: Int = 256

/**
 * Encodes the data length (Nc) for extended length APDUs (Lc1, Lc2).
 *
 * @param nc The data length (number of data bytes).
 * @return A ByteArray containing the encoded length (2 bytes).
 * @throws IllegalArgumentException if nc is negative.
 */
private fun encodeDataLengthExtended(nc: Int): ByteArray {
    require(nc >= 0) { "Data length (nc) must not be negative" }
    return byteArrayOf(
        0x0,
        (nc shr 8).toByte(),
        (nc and 0xFF).toByte(),
    )
}

/**
 * Encodes the data length (Nc) for short length APDUs (Lc).
 *
 * @param nc The data length (number of data bytes).
 * @return A ByteArray containing the encoded length (1 byte).
 * @throws IllegalArgumentException if nc is negative or greater than 255.
 */
private fun encodeDataLengthShort(nc: Int): ByteArray {
    require(nc in 0..255) { "Data length (nc) must be in range [0, 255] for short APDUs" }
    return byteArrayOf(nc.toByte())
}

/**
 * Encodes the expected length (Ne) for extended length APDUs (Le1, Le2).
 *
 * @param ne The expected length (number of expected response bytes).
 * @return A ByteArray containing the encoded length (2 bytes).
 *         If ne is EXPECTED_LENGTH_WILDCARD_EXTENDED, returns [0x00, 0x00].
 * @throws IllegalArgumentException if ne is negative or greater than 65536.
 */
private fun encodeExpectedLengthExtended(ne: Int): ByteArray {
    require(ne in 0..EXPECTED_LENGTH_WILDCARD_EXTENDED) {
        "Expected length (ne) must be in range [0, $EXPECTED_LENGTH_WILDCARD_EXTENDED]"
    }
    return if (ne != EXPECTED_LENGTH_WILDCARD_EXTENDED) {
        byteArrayOf((ne shr 8).toByte(), (ne and 0xFF).toByte()) // l1, l2
    } else {
        byteArrayOf(0x0, 0x0)
    }
}

/**
 * Encodes the expected length (Ne) for short length APDUs (Le).
 *
 * @param ne The expected length (number of expected response bytes).
 * @return A ByteArray containing the encoded length (1 byte).
 *         If ne is EXPECTED_LENGTH_WILDCARD_EXTENDED, returns 0x00.
 * @throws IllegalArgumentException if ne is negative or greater than 256.
 */
private fun encodeExpectedLengthShort(ne: Int): ByteArray {
    require(ne in 0..EXPECTED_LENGTH_WILDCARD_EXTENDED) {
        "Expected length (ne) must be in range [0, $EXPECTED_LENGTH_WILDCARD_EXTENDED]"
    }
    return byteArrayOf(
        if (ne != EXPECTED_LENGTH_WILDCARD_EXTENDED) {
            ne.toByte()
        } else {
            0x0
        },
    )
}

/**
 * An APDU (Application Protocol Data Unit) Command per ISO/IEC 7816-4.
 * Command APDU encoding options:
 *
 * ```
 * case 1:  |CLA|INS|P1 |P2 |                                 len = 4
 * case 2s: |CLA|INS|P1 |P2 |LE |                             len = 5
 * case 3s: |CLA|INS|P1 |P2 |LC |...BODY...|                  len = 6..260
 * case 4s: |CLA|INS|P1 |P2 |LC |...BODY...|LE |              len = 7..261
 * case 2e: |CLA|INS|P1 |P2 |00 |LE1|LE2|                     len = 7
 * case 3e: |CLA|INS|P1 |P2 |00 |LC1|LC2|...BODY...|          len = 8..65542
 * case 4e: |CLA|INS|P1 |P2 |00 |LC1|LC2|...BODY...|LE1|LE2|  len = 10..65544
 *
 * LE, LE1, LE2 may be 0x00.
 * LC must not be 0x00 and LC1|LC2 must not be 0x00|0x00
 * ```
 */
class CardCommandApdu(
    apduBytes: ByteArray,
    val rawNc: Int,
    val rawNe: Int?,
    val dataOffset: Int,
) {
    val apdu = apduBytes.copyOf()
        get() = field.copyOf()

    companion object {
        /**
         * Creates a CardCommandApdu for case 1, 2s or 2e.
         *
         * @param cla The class byte (CLA).
         * @param ins The instruction byte (INS).
         * @param p1 The parameter 1 byte (P1).
         * @param p2 The parameter 2 byte (P2).
         * @param ne The expected length (Ne) of the response, or null for case 1.
         * @return A new CardCommandApdu instance.
         * @throws IllegalArgumentException if any of the APDU header fields are out of range,
         *                                  or if the expected length is out of range.
         */
        fun ofOptions(
            cla: Int,
            ins: Int,
            p1: Int,
            p2: Int,
            ne: Int?,
        ) = ofOptions(cla = cla, ins = ins, p1 = p1, p2 = p2, data = null, ne = ne)

        /**
         * Creates a CardCommandApdu for case 1, 2s, 2e, 3s, 3e, 4s or 4e.
         *
         * @param cla The class byte (CLA).
         * @param ins The instruction byte (INS).
         * @param p1 The parameter 1 byte (P1).
         * @param p2 The parameter 2 byte (P2).
         * @param data The command data (body), or null for case 1, 2s or 2e.
         * @param ne The expected length (Ne) of the response, or null for case 3s or 3e.
         * @return A new CardCommandApdu instance.
         * @throws IllegalArgumentException if any of the APDU header fields are out of range,
         *                                  if the data length is out of range, or if the expected
         *                                  length is out of range.
         */
        @Suppress("detekt.LongMethod", "detekt.CyclomaticComplexMethod")
        fun ofOptions(
            cla: Int,
            ins: Int,
            p1: Int,
            p2: Int,
            data: ByteArray?,
            ne: Int?,
        ): CardCommandApdu {
            // Validate header fields
            require(!(cla < 0 || ins < 0 || p1 < 0 || p2 < 0)) {
                "APDU header fields must not be less than 0"
            }
            require(!(cla > 0xFF || ins > 0xFF || p1 > 0xFF || p2 > 0xFF)) {
                "APDU header fields must not be greater than 255 (0xFF)"
            }

            // Validate expected length
            ne?.let {
                require(ne <= EXPECTED_LENGTH_WILDCARD_EXTENDED && ne >= 0) {
                    "APDU response length is out of bounds [0, $EXPECTED_LENGTH_WILDCARD_EXTENDED]"
                }
            }

            var bytes = byteArrayOf()
            // Write header |CLA|INS|P1|P2|
            bytes += byteArrayOf(cla.toByte(), ins.toByte(), p1.toByte(), p2.toByte())

            return if (data != null) {
                val nc = data.size
                require(nc <= 65535) { "APDU command data length must not exceed 65535 bytes" }

                val dataOffset: Int
                val le: Int? // le1, le2
                if (ne != null) {
                    le = ne
                    // Case 4s or 4e
                    if (nc <= 255 && ne <= EXPECTED_LENGTH_WILDCARD_SHORT) {
                        // Case 4s
                        dataOffset = 5
                        bytes += encodeDataLengthShort(nc)
                        bytes += data
                        bytes += encodeExpectedLengthShort(ne)
                    } else {
                        // Case 4e
                        dataOffset = 7
                        bytes += encodeDataLengthExtended(nc)
                        bytes += data
                        bytes += encodeExpectedLengthExtended(ne)
                    }
                } else {
                    // Case 3s or 3e
                    le = null
                    if (nc <= 255) {
                        // Case 3s
                        dataOffset = 5
                        bytes += encodeDataLengthShort(nc)
                    } else {
                        // Case 3e
                        dataOffset = 7
                        bytes += encodeDataLengthExtended(nc)
                    }
                    bytes += data
                }

                CardCommandApdu(
                    apduBytes = bytes,
                    rawNc = nc,
                    rawNe = le,
                    dataOffset = dataOffset,
                )
            } else {
                // Data is null
                if (ne != null) {
                    // Case 2s or 2e
                    if (ne <= EXPECTED_LENGTH_WILDCARD_SHORT) {
                        // Case 2s
                        bytes += encodeExpectedLengthShort(ne)
                    } else {
                        // Case 2e
                        bytes += 0x0
                        bytes += encodeExpectedLengthExtended(ne)
                    }

                    CardCommandApdu(
                        apduBytes = bytes,
                        rawNc = 0,
                        rawNe = ne,
                        dataOffset = 0,
                    )
                } else {
                    // Case 1
                    CardCommandApdu(
                        apduBytes = bytes,
                        rawNc = 0,
                        rawNe = null,
                        dataOffset = 0,
                    )
                }
            }
        }
    }
}

/**
 * Represents a response APDU (Application Protocol Data Unit)received from a smart card,
 * as defined by ISO/IEC 7816-4.
 *
 * @property bytes The raw byte array of the received APDU.
 * @throws IllegalArgumentException if the provided byte array has less than 2 bytes.
 */
class CardResponseApdu(
    apdu: ByteArray,
) {
    /**
     * The raw byte array of the received APDU.
     */
    val bytes: ByteArray = apdu.copyOf()
        get() = field.copyOf()

    init {
        require(bytes.size >= 2) {
            "Response APDU must contain at least 2 bytes (status bytes SW1, SW2)"
        }
    }

    /**
     * The data bytes of the response.
     * This is a copy of the bytes excluding the status bytes (SW1, SW2).
     */
    val data: ByteArray
        get() = bytes.copyOfRange(0, bytes.size - 2)

    /**
     * The status byte 1 (SW1) of the response.
     * This is the second-to-last byte of the APDU.
     */
    private val sw1: Int
        get() = bytes[bytes.size - 2].toInt() and 0xFF

    /**
     * The status byte 2 (SW2) of the response.
     * This is the last byte of the APDU.
     */
    private val sw2: Int
        get() = bytes[bytes.size - 1].toInt() and 0xFF

    /**
     * The combined status word (SW) of the response.
     * This is a 16-bit value formed by concatenating SW1 and SW2 (SW1 << 8 | SW2).
     */
    val sw: Int
        get() = (sw1 shl 8) or sw2

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false
        other as CardResponseApdu
        return bytes.contentEquals(other.bytes)
    }

    override fun hashCode(): Int = bytes.contentHashCode()
}
