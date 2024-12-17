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

import kotlin.contracts.ExperimentalContracts
import kotlin.contracts.contract
import kotlin.experimental.and
import kotlin.js.JsExport
import kotlin.js.JsName

@JsExport
class Asn1DecoderException(
    override val message: String,
    override val cause: Throwable?,
) : IllegalArgumentException(message, cause) {
    @JsExport.Ignore
    constructor(message: String) : this(message, null)
}

@OptIn(ExperimentalStdlibApi::class)
internal val hexDebugFormat =
    HexFormat {
        number {
            prefix = "0x"
            removeLeadingZeros = true
        }
    }

/**
 * Constructs an [Asn1Decoder] from the given [data].
 * The [data] byte array will not be copied!
 */
@JsExport
class Asn1Decoder(
    private val data: ByteArray,
) {
    init {
        require(data.isNotEmpty()) { "Data must not be empty" }
    }

    /**
     * [ParserScope] implements the basic parsing functionality.
     *
     * Important:
     * [ParserScope] is treated as a mutable object throughout the entire time of calling [read] and
     * therefore unsafe to keep references to it or use it in the context of coroutines or threads.
     */
    inner class ParserScope(
        startOffset: Int,
        endOffset: Int,
    ) {
        var offset: Int = startOffset
            private set(value) {
                check(value <= endOffset) { "Offset must be <= `endOffset`" }
                field = value
            }

        var endOffset: Int = endOffset
            private set(value) {
                check(value >= offset) { "End offset must be >= `offset`" }
                field = value
            }

        val remainingLength get() = endOffset - offset

        /**
         * Throws an [Asn1DecoderException] with the result of calling [message].
         */
        @JsName("fail")
        inline fun fail(message: () -> String): Nothing = throw Asn1DecoderException(message())

        /**
         * Throws an [Asn1DecoderException] with the result of calling [message] and the [cause].
         */
        @JsName("failWithCause")
        inline fun fail(
            cause: Throwable,
            message: () -> String,
        ): Nothing = throw Asn1DecoderException(message(), cause)

        /**
         * Throws an [ParserException] if [value] is `false` with the result of calling [message].
         */
        @OptIn(ExperimentalContracts::class)
        inline fun check(
            value: Boolean,
            message: () -> String,
        ) {
            contract {
                returns() implies value
            }
            if (!value) fail(message)
        }

        /**
         * Advance with one of the [block]s and return the resulting [Asn1Object].
         * Returns [Result.failure] if no [block] was matched.
         */
        fun <T> advance(vararg block: ParserScope.() -> T): T {
            val originalOffset = offset
            val originalEndOffset = endOffset
            for (bl in block) {
                try {
                    return bl(this)
                } catch (e: Asn1DecoderException) {
                    // continue
                }
                offset = originalOffset
                endOffset = originalEndOffset
            }
            fail { "No block matched" }
        }

        /**
         * Optional parsing [block]. Returns `null` if [block] throws an [Asn1DecoderException].
         */
        fun <T> optional(block: ParserScope.() -> T): T? {
            val originalOffset = offset
            val originalEndOffset = endOffset
            return try {
                block(this)
            } catch (e: Asn1DecoderException) {
                offset = originalOffset
                endOffset = originalEndOffset

                null
            }
        }

        /**
         * Advance with the given [tag] and return the resulting [Asn1Object]. Throws an [ParserException] if the [tag] doesn't match.
         * @param tag the tag to advance with.
         */
        fun <T> Asn1Decoder.ParserScope.advanceWithTag(
            tagNumber: Int,
            tagClass: Int = 0x00,
            block: Asn1Decoder.ParserScope.() -> T,
        ): T {
            val tag = readTag()
            if (tag.tagNumber != tagNumber && tag.tagClass != tagClass) {
                fail {
                    "Expected tag `${Asn1Tag(tagClass, tagNumber)}` but got `$tag`"
                }
            }
            val length = readLength()
            val isInfiniteLength = length == -1

            val originalEndOffset = endOffset

            endOffset = if (isInfiniteLength) Int.MAX_VALUE else offset + length
            val result = block()

            when (isInfiniteLength) {
                false ->
                    if (endOffset != offset) fail { "Unparsed bytes remaining" }
                true ->
                    // check end of content `0x00 0x00` on infinite length
                    if (!readBytes(2).contentEquals(byteArrayOf(0x00, 0x00))) {
                        fail { "Infinite length object must be finished with `0x00 0x00`" }
                    }
            }

            endOffset = originalEndOffset

            return result
        }

        /**
         * Read one byte.
         */
        fun readByte(): Byte = data[offset++]

        /**
         * Read one bytes.
         */
        fun readBytes(length: Int): ByteArray {
            check(length >= 0) { "Length must be >= `0`. Is `$length`" }
            val data = data.copyOfRange(offset, offset + length)
            offset += length
            return data
        }

        /**
         * Reads the next tag from the data, handling multi-byte tags.
         */
        fun readTag(): Asn1Tag {
            // Read the first byte of the tag
            val firstByte = data[offset++].toInt() and 0xFF
            val tagClassAndConstructed = firstByte and 0xE0 // Class and constructed bits
            val tagNumber = firstByte and 0x1F // Low 5 bits

            return if (tagNumber == 0x1F) {
                // Multi-byte tag: Read until MSB is 0
                var value = 0
                do {
                    if (offset >= endOffset) fail { "Unexpected end of data in tag" }
                    val nextByte = data[offset++].toInt() and 0xFF
                    value = (value shl 7) or (nextByte and 0x7F)
                } while (nextByte and 0x80 != 0)
                Asn1Tag(tagClassAndConstructed, value)
            } else {
                // Single-byte tag
                Asn1Tag(tagClassAndConstructed, tagNumber)
            }
        }

        /**
         * Read the length. Returns `-1` for infinite length.
         */
        fun readLength(): Int {
            val lengthByte = readByte().toInt() and 0xFF
            return when {
                lengthByte == 0x80 -> -1
                lengthByte and 0x80 == 0 -> {
                    // short form length
                    lengthByte
                }
                else -> {
                    // long form length
                    val lengthSize = lengthByte and 0x7F
                    readInt(lengthSize, false)
                }
            }
        }

        /**
         * Read [length] bytes as an integer.
         */
        fun readInt(
            length: Int,
            signed: Boolean = true,
        ): Int {
            check(length in 1..4) { "Length must be in range of [1, 4]. Is `$length`" }
            val bytes = data.copyOfRange(offset, offset + length)
            offset += length

            var result = bytes[0].toInt()
            result =
                if (signed && result and 0x80 != 0) { // Check if the sign bit is set
                    result or -0x100 // Sign extend for negative numbers
                } else {
                    result and 0xFF // Clear the sign bit
                }

            for (i in 1 until length) {
                result = (result shl 8) or (bytes[i].toInt() and 0xFF)
            }

            return result
        }

        /**
         * Skip [length] bytes.
         */
        fun skip(length: Int) {
            offset += length
        }

        /**
         * Skip [length] bytes.
         */
        fun skipToEnd() {
            check(endOffset != Int.MAX_VALUE) { "Can't skip bytes inside infinite length object" }
            offset = endOffset
        }
    }

    fun <T> read(block: ParserScope.() -> T): T {
        val scope =
            ParserScope(
                startOffset = 0,
                endOffset = data.size,
            )
        return block(scope)
    }
}

/**
 * Read [Asn1Type.BOOLEAN].
 */
@JsExport
fun Asn1Decoder.ParserScope.readBoolean(): Boolean =
    advanceWithTag(Asn1Type.BOOLEAN) {
        readByte() == 0xFF.toByte()
    }

/**
 * Read [Asn1Type.INTEGER].
 */
@JsExport
fun Asn1Decoder.ParserScope.readInt(): Int =
    advanceWithTag(Asn1Type.INTEGER) {
        readInt(remainingLength)
    }

/**
 * Read [Asn1Type.BIT_STRING].
 */
@JsExport
fun Asn1Decoder.ParserScope.readBitString(): ByteArray =
    advanceWithTag(Asn1Type.BIT_STRING) {
        val unusedBits = readByte().toInt()
        if (unusedBits !in 0..7) fail { "Invalid unused bit count: $unusedBits" }
        val bitString = readBytes(remainingLength)
        if (unusedBits == 0) {
            bitString
        } else {
            bitString.copyOfRange(0, bitString.size - 1) +
                (bitString.last() and ((0xFF shl unusedBits).toByte()))
        }
    }

/**
 * Read [Asn1Type.UTF8_STRING].
 */
@JsExport
fun Asn1Decoder.ParserScope.readUtf8String(): String =
    advanceWithTag(Asn1Type.OCTET_STRING) {
        try {
            readBytes(remainingLength).decodeToString()
        } catch (e: Exception) {
            fail(e) { "Malformed UTF-8 string" }
        }
    }

/**
 * Read [Asn1Type.VISIBLE_STRING].
 */
@JsExport
fun Asn1Decoder.ParserScope.readVisibleString(): String =
    advanceWithTag(Asn1Type.VISIBLE_STRING) {
        readBytes(remainingLength).decodeToString()
    }

/**
 * Read [Asn1Type.OCTET_STRING].
 */
@JsExport
fun Asn1Decoder.ParserScope.readOctetString(): ByteArray =
    advanceWithTag(Asn1Type.OCTET_STRING) {
        readBytes(remainingLength)
    }