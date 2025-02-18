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

package de.gematik.openhealth.smartcard.tagobjects

import de.gematik.openhealth.asn1.Asn1Encoder
import de.gematik.openhealth.asn1.Asn1Tag
import de.gematik.openhealth.asn1.writeTaggedObject

/**
 * Data object with TAG 87
 *
 * @param data byte array with extracted data from plain CommandApdu or encrypted ResponseApdu
 * @param tag int with extracted tag number
 */
class DataObject(
    val data: ByteArray,
    val tag: Asn1Tag,
) {
    init {
        require(tag.tagClass == Asn1Tag.CONTEXT_SPECIFIC)
        require(tag.tagNumber == 0x07 || tag.tagNumber == 0x01)
    }

    val isEncrypted: Boolean = tag.tagNumber == 0x07

    val encoded: ByteArray
        get() =
            Asn1Encoder().write {
                writeTaggedObject(tagNumber = tag.tagNumber, tagClass = tag.tagClass) {
                    write(data)
                }
            }

    companion object {
        fun encrypted(data: ByteArray) =
            DataObject(data, Asn1Tag(tagClass = Asn1Tag.CONTEXT_SPECIFIC, tagNumber = 0x07))
    }
}
