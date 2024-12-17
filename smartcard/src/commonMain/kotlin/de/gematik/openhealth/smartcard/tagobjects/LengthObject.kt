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

package de.gematik.openhealth.smartcard.tagobjects

import de.gematik.openhealth.asn1.Asn1Encoder
import de.gematik.openhealth.asn1.writeTaggedObject
import de.gematik.openhealth.smartcard.command.EXPECTED_LENGTH_WILDCARD_SHORT

private const val DO_97_TAG = 0x17
private const val BYTE_MASK = 0xFF
private const val BYTE_VALUE = 8

/**
 * Length object with TAG 97
 *
 * @param le extracted expected length from plain CommandApdu
 */
class LengthObject(
    le: Int,
) {
    private val leData: ByteArray =
        when {
            le == EXPECTED_LENGTH_WILDCARD_SHORT -> {
                byteArrayOf(0x00)
            }
            le > EXPECTED_LENGTH_WILDCARD_SHORT -> {
                byteArrayOf(
                    (le shr BYTE_VALUE and BYTE_MASK).toByte(),
                    (le and BYTE_MASK).toByte(),
                )
            }
            else -> {
                byteArrayOf(le.toByte())
            }
        }

    val encoded: ByteArray
        get() {
            val encoder = Asn1Encoder()
            return encoder.write {
                writeTaggedObject(DO_97_TAG) {
                    write(leData) // Write the length data as an octet string
                }
            }
        }
}