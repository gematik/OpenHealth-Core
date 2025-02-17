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

package de.gematik.openhealth.asn1

import kotlin.experimental.or
import kotlin.js.JsExport

/**
 * Read [Asn1Type.OBJECT_IDENTIFIER].
 */
@JsExport
fun Asn1Decoder.ParserScope.readObjectIdentifier(): String =
    advanceWithTag(Asn1Type.OBJECT_IDENTIFIER) {
        val bytes = readBytes(remainingLength)

        if (bytes.isEmpty()) fail { "Encoded OID cannot be empty" }

        val firstByte = bytes[0].toInt() and 0xFF
        val first = firstByte / 40
        val second = firstByte % 40

        val parts = mutableListOf<Int>()

        parts.add(first)
        parts.add(second)

        // Decode the remaining bytes
        var value = 0
        for (i in 1 until bytes.size) {
            val byte = bytes[i].toInt() and 0xFF
            value = (value shl 7) or (byte and 0x7F)

            // Check if this is the last byte in the current value
            if (byte and 0x80 == 0) {
                parts.add(value)
                value = 0
            }
        }

        if (value != 0) fail { "Invalid OID encoding: unfinished encoding" }

        parts.joinToString(".")
    }

/**
 * Write [Asn1Type.OBJECT_IDENTIFIER].
 */
@JsExport
fun Asn1Encoder.WriterScope.writeObjectIdentifier(oid: String) {
    writeTaggedObject(Asn1Type.OBJECT_IDENTIFIER) {
        val parts = oid.split(".").map { it.toIntOrNull() ?: fail { "Invalid OID part: $it" } }

        if (parts.size < 2) fail { "OID must have at least two components" }

        val first = parts[0]
        val second = parts[1]

        if (first !in 0..2) fail { "OID first part must be 0, 1, or 2" }
        if (second !in 0..39 &&
            first < 2
        ) {
            fail { "OID second part must be 0-39 for first part 0 or 1" }
        }

        // Encode the first two parts as a single byte or extend if necessary
        val firstByte = first * 40 + second

        writeMultiByte(firstByte)

        // Encode the remaining parts
        for (i in 2 until parts.size) {
            writeMultiByte(parts[i])
        }
    }
}

private fun Asn1Encoder.WriterScope.writeMultiByte(integer: Int) {
    var value = integer
    val bytes = mutableListOf<Byte>()

    do {
        bytes.add((value and 0x7F).toByte())
        value = value shr 7
    } while (value > 0)

    // Write bytes in reverse order, setting the MSB for all but the last byte
    bytes.asReversed().forEachIndexed { index, byte ->
        write(if (index == bytes.lastIndex) byte else (byte or 0x80.toByte()))
    }
}
