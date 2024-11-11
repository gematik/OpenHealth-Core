/*
 * Copyright 2025 gematik GmbH
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
 * Represents an APDU (Application Protocol Data Unit) Command as per ISO/IEC 7816-4.
 *
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
 * LC must not be 0x00 and LC1|LC2 must not be 0x00|0x00.
 * ```
 */
class CardCommandApdu private constructor(
    apdu: ByteArray,
    val dataLength: Int,
    val dataOffset: Int,
    val cla: Int,
    val ins: Int,
    val p1: Int,
    val p2: Int,
    val data: ByteArray?,
    val ne: Int?,
) {
    // Returns a defensive copy of the APDU byte array.
    val apdu: ByteArray = apdu.copyOf()
        get() = field.copyOf()

    val expectedLength: Int? get() = ne

    /**
     * Companion object to create instances of CardCommandApdu.
     */
    companion object {
        /**
         * Creates a CardCommandApdu for cases 1, 2s, or 2e.
         *
         * @param cla The class byte (CLA).
         * @param ins The instruction byte (INS).
         * @param p1 The parameter 1 byte (P1).
         * @param p2 The parameter 2 byte (P2).
         * @param ne The expected response length (Ne), or null for case 1.
         * @return A new instance of CardCommandApdu.
         * @throws IllegalArgumentException if any header field or expected length is out of range.
         */
        fun ofOptions(
            cla: Int,
            ins: Int,
            p1: Int,
            p2: Int,
            ne: Int?,
        ): CardCommandApdu = ofOptions(cla, ins, p1, p2, data = null, ne = ne)

        /**
         * Creates a CardCommandApdu for cases 1, 2s, 2e, 3s, 3e, 4s, or 4e.
         *
         * @param cla The class byte (CLA).
         * @param ins The instruction byte (INS).
         * @param p1 The parameter 1 byte (P1).
         * @param p2 The parameter 2 byte (P2).
         * @param data The command data (body), or null for cases 1, 2s, or 2e.
         * @param ne The expected response length (Ne), or null for cases 3s or 3e.
         * @return A new instance of CardCommandApdu.
         * @throws IllegalArgumentException if any header field, data length, or expected length is out of range.
         */
        @Suppress("detekt.LongMethod", "detekt.CyclomaticComplexMethod", "NestedBlockDepth")
        fun ofOptions(
            cla: Int,
            ins: Int,
            p1: Int,
            p2: Int,
            data: ByteArray?,
            ne: Int?,
        ): CardCommandApdu {
            // Validate header fields are within the range 0..255.
            require(cla in 0..0xFF && ins in 0..0xFF && p1 in 0..0xFF && p2 in 0..0xFF) {
                "APDU header fields must be in the range 0..255"
            }

            // Validate the expected length (Ne), if provided.
            ne?.let {
                require(it in 0..EXPECTED_LENGTH_WILDCARD_EXTENDED) {
                    "APDU response length must be within [0, $EXPECTED_LENGTH_WILDCARD_EXTENDED]"
                }
            }

            var apdu = byteArrayOf()
            // Append header: |CLA|INS|P1|P2|
            apdu += byteArrayOf(cla.toByte(), ins.toByte(), p1.toByte(), p2.toByte())

            val dataLength: Int
            val dataOffset: Int

            if (data != null) {
                dataLength = data.size
                require(
                    dataLength < EXPECTED_LENGTH_WILDCARD_EXTENDED,
                ) { "APDU command data length must not exceed 65535 bytes" }

                if (ne != null) {
                    // Cases 4s or 4e: Both data and expected length are present.
                    if (dataLength < EXPECTED_LENGTH_WILDCARD_SHORT &&
                        ne <= EXPECTED_LENGTH_WILDCARD_SHORT
                    ) {
                        // Case 4s: Short data and expected length.
                        dataOffset = 5
                        apdu += encodeDataLengthShort(dataLength)
                        apdu += data
                        apdu += encodeExpectedLengthShort(ne)
                    } else {
                        // Case 4e: Extended data or expected length.
                        dataOffset = 7
                        apdu += encodeDataLengthExtended(dataLength)
                        apdu += data
                        apdu += encodeExpectedLengthExtended(ne)
                    }
                } else {
                    // Cases 3s or 3e: Only data is present.
                    if (dataLength < EXPECTED_LENGTH_WILDCARD_SHORT) {
                        // Case 3s: Short data length.
                        dataOffset = 5
                        apdu += encodeDataLengthShort(dataLength)
                    } else {
                        // Case 3e: Extended data length.
                        dataOffset = 7
                        apdu += encodeDataLengthExtended(dataLength)
                    }
                    apdu += data
                }
            } else {
                // No data provided.
                if (ne != null) {
                    // Cases 2s or 2e: Expected length only.
                    if (ne <= EXPECTED_LENGTH_WILDCARD_SHORT) {
                        // Case 2s: Short expected length.
                        apdu += encodeExpectedLengthShort(ne)
                    } else {
                        // Case 2e: Extended expected length.
                        apdu += 0x0
                        apdu += encodeExpectedLengthExtended(ne)
                    }

                    dataLength = 0
                    dataOffset = 0
                } else {
                    // Case 1: Header only.
                    dataLength = 0
                    dataOffset = 0
                }
            }
            return CardCommandApdu(
                apdu = apdu,
                dataLength = dataLength,
                dataOffset = dataOffset,
                cla = cla,
                ins = ins,
                p1 = p1,
                p2 = p2,
                data = data,
                ne = ne,
            )
        }

        /**
         * Creates a CardCommandApdu instance from a raw APDU byte array.
         *
         * @param apdu The raw APDU byte array.
         * @return A CardCommandApdu instance representing the APDU.
         * @throws IllegalArgumentException if the APDU is invalid or its length is inconsistent.
         */
        @Suppress(
            "detekt.LongMethod",
            "detekt.CyclomaticComplexMethod",
            "detekt.NestedBlockDepth",
        )
        fun ofApdu(apdu: ByteArray): CardCommandApdu {
            require(apdu.size >= 4) { "APDU must be at least 4 bytes long" }

            val dataLength: Int
            val expectedLength: Int?
            val dataOffset: Int

            when {
                // Case 1: Only the header is present.
                apdu.size == 4 -> {
                    dataLength = 0
                    expectedLength = null
                    dataOffset = 0
                }

                // Case 2s: Only expected length is present.
                apdu.size == 5 -> {
                    val li = apdu[4].toInt() and 0xFF
                    val ne = if (li == 0) EXPECTED_LENGTH_WILDCARD_SHORT else li

                    dataLength = 0
                    expectedLength = ne
                    dataOffset = 0
                }

                // Short length cases: non-zero length indicator.
                (apdu[4].toInt() and 0xFF) != 0 -> {
                    val li = apdu[4].toInt() and 0xFF
                    when (apdu.size) {
                        4 + 1 + li -> {
                            // Case 3s: Data only.
                            dataLength = li
                            expectedLength = null
                            dataOffset = 5
                        }
                        4 + 2 + li -> {
                            // Case 4s: Data and expected length.
                            val ne =
                                if ((apdu.last().toInt() and 0xFF) == 0) {
                                    EXPECTED_LENGTH_WILDCARD_SHORT
                                } else {
                                    (apdu.last().toInt() and 0xFF)
                                }

                            dataLength = li
                            expectedLength = ne
                            dataOffset = 5
                        }
                        else -> throw IllegalArgumentException(
                            "Invalid APDU: length=${apdu.size}, lengthIndicator=$li",
                        )
                    }
                }

                // Extended length cases (lengthIndicator == 0).
                else -> {
                    require(apdu.size >= 7) {
                        "Invalid APDU: length=${apdu.size}, " +
                            "lengthIndicator=${apdu[4].toInt() and 0xFF}"
                    }
                    val dataLengthExtended =
                        ((apdu[5].toInt() and 0xFF) shl 8) or (apdu[6].toInt() and 0xFF)
                    if (apdu.size == 7) {
                        // Case 2e: Only expected length in extended format.
                        val ne =
                            if (dataLengthExtended == 0) {
                                EXPECTED_LENGTH_WILDCARD_EXTENDED
                            } else {
                                dataLengthExtended
                            }

                        dataLength = 0
                        expectedLength = ne
                        dataOffset = 0
                    } else {
                        require(dataLengthExtended != 0) {
                            "Invalid APDU: length=${apdu.size}, " +
                                "lengthIndicator=${apdu[4].toInt() and 0xFF}, " +
                                "extendedLength=$dataLengthExtended"
                        }
                        when (apdu.size) {
                            4 + 3 + dataLengthExtended -> {
                                // Case 3e: Data only (extended).
                                dataLength = dataLengthExtended
                                expectedLength = null
                                dataOffset = 7
                            }
                            4 + 5 + dataLengthExtended -> {
                                // Case 4e: Data and expected length (extended).
                                val off = apdu.size - 2
                                val expectedLengthIndicator =
                                    ((apdu[off].toInt() and 0xFF) shl 8) or
                                        (apdu[off + 1].toInt() and 0xFF)
                                val ne =
                                    if (expectedLengthIndicator == 0) {
                                        EXPECTED_LENGTH_WILDCARD_EXTENDED
                                    } else {
                                        expectedLengthIndicator
                                    }

                                dataLength = dataLengthExtended
                                expectedLength = ne
                                dataOffset = 7
                            }
                            else -> throw IllegalArgumentException(
                                "Invalid APDU: length=${apdu.size}, " +
                                    "lengthIndicator=${apdu[4].toInt() and 0xFF}, " +
                                    "extendedLength=$dataLengthExtended",
                            )
                        }
                    }
                }
            }

            // Extract header bytes.
            val cla = apdu[0].toInt() and 0xFF
            val ins = apdu[1].toInt() and 0xFF
            val p1 = apdu[2].toInt() and 0xFF
            val p2 = apdu[3].toInt() and 0xFF

            // Extract data bytes if present.
            val data =
                if (dataLength > 0) {
                    apdu.copyOfRange(dataOffset, dataOffset + dataLength)
                } else {
                    null
                }

            return CardCommandApdu(
                apdu = apdu,
                dataLength = dataLength,
                dataOffset = dataOffset,
                cla = cla,
                ins = ins,
                p1 = p1,
                p2 = p2,
                data = data,
                ne = expectedLength,
            )
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
