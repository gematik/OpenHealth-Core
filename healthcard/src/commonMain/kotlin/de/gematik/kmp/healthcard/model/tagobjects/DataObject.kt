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

package de.gematik.kmp.healthcard.model.tagobjects

import de.gematik.kmp.asn1.Asn1Encoder
import de.gematik.kmp.asn1.writeTaggedObject

private const val DO_87_TAG = 0x07
private const val DO_81_EXTRACTED_TAG = 0x81
private const val DO_81_TAG = 0x01

/**
 * Data object with TAG 87
 *
 * @param data byte array with extracted data from plain CommandApdu or encrypted ResponseApdu
 * @param tag int with extracted tag number
 */
class DataObject(
    val data: ByteArray,
    val tag: Byte = 0,
) {
    val encoded: ByteArray
        get() {
            val encoder = Asn1Encoder()
            return encoder.write {
                val actualTag = if (tag == DO_81_EXTRACTED_TAG.toByte()) DO_81_TAG else DO_87_TAG
                writeTaggedObject(actualTag) {
                    write(data) // Write the raw data as an octet string
                }
            }
        }
}