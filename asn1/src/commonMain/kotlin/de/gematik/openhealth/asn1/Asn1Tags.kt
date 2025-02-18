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

package de.gematik.openhealth.asn1

import kotlin.js.JsExport

@JsExport
object Asn1Type {
    const val BOOLEAN = 0x01
    const val INTEGER = 0x02
    const val BIT_STRING = 0x03
    const val OCTET_STRING = 0x04
    const val NULL = 0x05
    const val OBJECT_IDENTIFIER = 0x06
    const val OBJECT_DESCRIPTOR = 0x07
    const val EXTERNAL = 0x08
    const val REAL = 0x09
    const val ENUMERATED = 0x0A
    const val EMBEDDED_PDV = 0x0B
    const val UTF8_STRING = 0x0C
    const val RELATIVE_OID = 0x0D
    const val TIME = 0x0E
    const val SEQUENCE = 0x10
    const val SET = 0x11
    const val NUMERIC_STRING = 0x12
    const val PRINTABLE_STRING = 0x13
    const val TELETEX_STRING = 0x14
    const val VIDEOTEX_STRING = 0x15
    const val IA5_STRING = 0x16
    const val UTC_TIME = 0x17
    const val GENERALIZED_TIME = 0x18
    const val GRAPHIC_STRING = 0x19
    const val VISIBLE_STRING = 0x1A
    const val GENERAL_STRING = 0x1B
    const val UNIVERSAL_STRING = 0x1C
    const val CHARACTER_STRING = 0x1D
    const val BMP_STRING = 0x1E
    const val DATE = 0x1F
    const val TIME_OF_DAY = 0x20
    const val DATE_TIME = 0x21
    const val DURATION = 0x22
}

@JsExport
data class Asn1Tag(
    val tagClass: Int,
    val tagNumber: Int,
) {
    @OptIn(ExperimentalStdlibApi::class)
    override fun toString(): String =
        "Asn1Tag(tagClass=${tagClass.toHexString(hexDebugFormat)}, " +
            "tagNumber=${tagNumber.toHexString(hexDebugFormat)})"

    companion object {
        const val CONSTRUCTED = 0x20

        const val APPLICATION = 0x40
        const val CONTEXT_SPECIFIC = 0x80
        const val PRIVATE = 0xC0
    }
}
