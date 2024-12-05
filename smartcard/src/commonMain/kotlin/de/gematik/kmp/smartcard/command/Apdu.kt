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

@file:Suppress("MagicNumber")

package de.gematik.kmp.smartcard.command

/**
 * Value for when wildcardShort for expected length encoding is needed
 */
const val EXPECTED_LENGTH_WILDCARD_EXTENDED: Int = 65536
const val EXPECTED_LENGTH_WILDCARD_SHORT: Int = 256

private fun encodeDataLengthExtended(nc: Int): ByteArray =
    byteArrayOf(
        0x0,
        (nc shr 8).toByte(),
        (nc and 0xFF).toByte(),
    )

private fun encodeDataLengthShort(nc: Int): ByteArray = byteArrayOf(nc.toByte())

private fun encodeExpectedLengthExtended(ne: Int): ByteArray =
    if (ne != EXPECTED_LENGTH_WILDCARD_EXTENDED) { // == 65536
        byteArrayOf((ne shr 8).toByte(), (ne and 0xFF).toByte()) // l1, l2
    } else {
        byteArrayOf(0x0, 0x0)
    }

private fun encodeExpectedLengthShort(ne: Int): ByteArray =
    byteArrayOf(
        if (ne != EXPECTED_LENGTH_WILDCARD_EXTENDED) {
            ne.toByte()
        } else {
            0x0
        },
    )

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
    private val _apduBytes = apduBytes.copyOf()
    val bytes
        get() = _apduBytes.copyOf()

    companion object {
        fun ofOptions(
            cla: Int,
            ins: Int,
            p1: Int,
            p2: Int,
            ne: Int?,
        ) = ofOptions(cla = cla, ins = ins, p1 = p1, p2 = p2, data = null, ne = ne)

        fun ofOptions(
            cla: Int,
            ins: Int,
            p1: Int,
            p2: Int,
            data: ByteArray?,
            ne: Int?,
        ): CardCommandApdu {
            require(!(cla < 0 || ins < 0 || p1 < 0 || p2 < 0)) {
                "APDU header fields must not be less than 0"
            }
            require(!(cla > 0xFF || ins > 0xFF || p1 > 0xFF || p2 > 0xFF)) {
                "APDU header fields must not be greater than 255 (0xFF)"
            }
            ne?.let {
                require(ne <= EXPECTED_LENGTH_WILDCARD_EXTENDED || ne >= 0) {
                    "APDU response length is out of bounds [0, 65536]"
                }
            }

            var bytes = byteArrayOf(cla.toByte(), ins.toByte(), p1.toByte(), p2.toByte())

            return if (data != null) {
                val nc = data.size
                require(nc <= 65535) { "ADPU command data length must not exceed 65535 bytes" }

                val dataOffset: Int
                val le: Int? // le1, le2
                if (ne != null) {
                    le = ne
                    // case 4s or 4e
                    if (nc <= 255 && ne <= EXPECTED_LENGTH_WILDCARD_SHORT) {
                        // case 4s
                        dataOffset = 5
                        bytes += encodeDataLengthShort(nc)
                        bytes += data
                        bytes += encodeExpectedLengthShort(ne)
                    } else {
                        // case 4e
                        dataOffset = 7
                        bytes += encodeDataLengthExtended(nc)
                        bytes += data
                        bytes += encodeExpectedLengthExtended(ne)
                    }
                } else {
                    // case 3s or 3e
                    le = null
                    if (nc <= 255) {
                        // case 3s
                        dataOffset = 5
                        bytes += encodeDataLengthShort(nc)
                    } else {
                        // case 3e
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
                // data empty
                if (ne != null) {
                    // case 2s or 2e
                    if (ne <= EXPECTED_LENGTH_WILDCARD_SHORT) {
                        // case 2s
                        // 256 is encoded 0x0
                        bytes += encodeExpectedLengthShort(ne)
                    } else {
                        // case 2e
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
                    // case 1
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

    override fun toString(): String = "Apdu.cla=${_apduBytes[0]})"
}

/**
 * APDU Response
 */
class CardResponseApdu(
    apdu: ByteArray,
) {
    init {
        require(
            apdu.size >= 2,
        ) { "Response APDU must not have less than 2 bytes (status bytes SW1, SW2)" }
    }

    private val apdu = apdu.copyOf()

    val nr: Int
        get() = apdu.size - 2

    val data: ByteArray
        get() = apdu.copyOfRange(0, apdu.size - 2)

    val sw1: Int
        get() = apdu[apdu.size - 2].toInt() and 0xFF

    val sw2: Int
        get() = apdu[apdu.size - 1].toInt() and 0xFF

    val sw: Int
        get() = sw1 shl 8 or sw2

    val bytes: ByteArray
        get() = apdu.copyOf()

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as CardResponseApdu

        return apdu.contentEquals(other.apdu)
    }

    override fun hashCode(): Int = apdu.contentHashCode()
}