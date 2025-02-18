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
 * Status object with TAG 99
 *
 * @param statusBytes byte array with extracted response status from encrypted ResponseApdu
 */
class StatusObject(
    private val statusBytes: ByteArray,
) {
    val encoded: ByteArray
        get() =
            Asn1Encoder().write {
                writeTaggedObject(0x19, Asn1Tag.CONTEXT_SPECIFIC) {
                    write(statusBytes)
                }
            }
}
