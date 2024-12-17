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
import kotlin.js.JsName

@JsExport
class Asn1EncoderException(
    override val message: String,
    override val cause: Throwable?,
) : IllegalArgumentException(message, cause) {
    @JsExport.Ignore
    constructor(message: String) : this(message, null)
}

@JsExport
class Asn1Encoder {
    class WriterScope {
        var data = ByteArray(0)
            private set

        /**
         * Throws an [Asn1EncoderException] with the result of calling [message].
         */
        @JsName("fail")
        inline fun fail(message: () -> String): Nothing = throw Asn1EncoderException(message())

        @JsName("writeByte")
        fun write(byte: Byte) {
            data += byte
        }

        @JsName("writeBytes")
        fun write(bytes: ByteArray) {
            data += bytes
        }

        @JsName("writeInt")
        fun write(integer: Int) {
            val bytes = mutableListOf<Byte>()
            var value = integer
            while (value < -0x80 || value >= 0x80) {
                bytes.add((value and 0xFF).toByte())
                value /= 0x100
            }
            bytes.add((value and 0xFF).toByte())

            // Ensure big endian order
            for (byte in bytes.reversed()) {
                write(byte)
            }
        }

        @JsName("writeScope")
        fun write(other: WriterScope) {
            // length
            write(other.data.size)
            // value
            write(other.data)
        }
    }

    fun write(block: WriterScope.() -> Unit): ByteArray {
        val scope = WriterScope()
        block(scope)
        return scope.data
    }
}

/**
 * Write the encoded tag directly, handling multi-byte encoding for large tags.
 */
fun Asn1Encoder.WriterScope.writeTag(
    tagNumber: Int,
    tagClass: Int = 0x00,
) {
    if (tagNumber < 0x1F) {
        // Single-byte tag
        write((tagNumber or tagClass).toByte())
    } else {
        // Multi-byte tag
        write((tagClass or 0x1F).toByte())

        // Collect encoded bytes in reverse order
        val encodedBytes = mutableListOf<Byte>()
        var value = tagNumber
        do {
            encodedBytes.add((value and 0x7F).toByte())
            value = value ushr 7
        } while (value > 0)

        // Write bytes in big endian order
        for (i in encodedBytes.size - 1 downTo 0) {
            val byte = encodedBytes[i]
            if (i > 0) {
                write(byte or 0x80.toByte()) // Set high-order bit for all but the last byte
            } else {
                write(byte)
            }
        }
    }
}

/**
 * Write an ASN.1 tagged object.
 */
fun Asn1Encoder.WriterScope.writeTaggedObject(
    tagNumber: Int,
    tagClass: Int = 0x00,
    block: Asn1Encoder.WriterScope.() -> Unit,
) {
    // TODO OPEN-2: Overload impl with Asn1Tag for a more convenient api

    // tag
    writeTag(tagNumber, tagClass)
    val scope = Asn1Encoder.WriterScope()
    block(scope)
    // length + value
    write(scope)
}

/**
 * Write an ASN.1 integer.
 */
fun Asn1Encoder.WriterScope.writeInt(value: Int) {
    writeTaggedObject(Asn1Type.INTEGER) {
        write(value)
    }
}

/**
 * Write an ASN.1 boolean.
 */
fun Asn1Encoder.WriterScope.writeBoolean(value: Boolean) {
    writeTaggedObject(Asn1Type.BOOLEAN) {
        write(if (value) 0xFF.toByte() else 0x00)
    }
}

/**
 * Write an ASN.1 bit string.
 */
fun Asn1Encoder.WriterScope.writeBitString(
    value: ByteArray,
    unusedBits: Int = 0,
) {
    if (unusedBits !in 0..7) fail { "Invalid unused bit count: $unusedBits" }
    writeTaggedObject(Asn1Type.BIT_STRING) {
        write(byteArrayOf(unusedBits.toByte()) + value)
    }
}

/**
 * Write an ASN.1 octet string.
 */
fun Asn1Encoder.WriterScope.writeOctetString(value: ByteArray) {
    writeTaggedObject(Asn1Type.OCTET_STRING) {
        write(value)
    }
}

/**
 * Write an ASN.1 utf8 string.
 */
fun Asn1Encoder.WriterScope.writeUtf8String(value: String) {
    writeTaggedObject(Asn1Type.UTF8_STRING) {
        write(value.encodeToByteArray())
    }
}