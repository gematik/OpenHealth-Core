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

package de.gematik.openhealth.smartcard.card

/**
 * The format 2 PIN block has been specified for use with IC cards. The format 2 PIN block shall only be used in
 * an offline environment and shall not be used for online PIN verification. This PIN block is constructed by
 * concatenation of two fields: the plain text PIN field and the filler field.
 *
 * @see "ISO 9564-1"
 */

private const val NIBBLE_SIZE = 4
private const val MIN_PIN_LEN = 4 // specSpec_COS#N008.000
private const val MAX_PIN_LEN = 12 // specSpec_COS#N008.000
private const val FORMAT_PIN_2_ID = 0x02 shl NIBBLE_SIZE // specSpec_COS#N008.100
private const val FORMAT2_PIN_SIZE = 8
private const val FORMAT2_PIN_FILLER = 0x0F
private const val MIN_DIGIT = 0 // specSpec_COS#N008.000
private const val MAX_DIGIT = 9 // specSpec_COS#N008.000
private const val STRING_INT_OFFSET = 48

/**
 * Represents an encrypted PIN in format 2.
 *
 * The format 2 PIN block is used with IC cards in an offline environment and is constructed by
 * concatenating the plain text PIN field and a filler field.
 *
 * @property pin The PIN string to be encrypted. The PIN must be between 4 and 12 digits long.
 */
class EncryptedPinFormat2(
    pin: String,
) {
    val bytes: ByteArray
        get() = field.copyOf()

    init {
        val intPin = pin.map { it.code - STRING_INT_OFFSET }

        require(intPin.size >= MIN_PIN_LEN) {
            "PIN length is too short, min length is " + MIN_PIN_LEN + ", but was " + intPin.size
        }
        require(intPin.size <= MAX_PIN_LEN) {
            "PIN length is too long, max length is " + MAX_PIN_LEN + ", but was " + intPin.size
        }

        intPin.forEach {
            require(it in MIN_DIGIT..MAX_DIGIT) {
                "PIN digit value is out of range of a decimal digit: ${(it + STRING_INT_OFFSET).toChar()}"
            }
        }

        val format2 = IntArray(FORMAT2_PIN_SIZE) // specSpec_COS#N008.100
        format2[0] = FORMAT_PIN_2_ID + intPin.size
        for (i in intPin.indices) {
            format2[1 + i / 2] +=
                if ((i + 2) % 2 == 0) {
                    intPin[i] shl NIBBLE_SIZE
                } else {
                    intPin[i]
                }
        }
        for (i in intPin.size until 2 * FORMAT2_PIN_SIZE - 2) {
            format2[1 + i / 2] +=
                if (i % 2 == 0) {
                    FORMAT2_PIN_FILLER shl NIBBLE_SIZE
                } else {
                    FORMAT2_PIN_FILLER
                }
        }

        val b = ByteArray(FORMAT2_PIN_SIZE)
        for (i in b.indices) {
            b[i] = format2[i].toByte()
        }
        bytes = b
    }
}
