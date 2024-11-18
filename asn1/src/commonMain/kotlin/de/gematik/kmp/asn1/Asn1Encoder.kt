package de.gematik.kmp.asn1

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
 * Write an ASN.1 tagged object.
 */
fun Asn1Encoder.WriterScope.writeTaggedObject(
    tag: Int,
    block: Asn1Encoder.WriterScope.() -> Unit,
) {
    // tag
    write(tag.toByte())
    val scope = Asn1Encoder.WriterScope()
    block(scope)
    // length + value
    write(scope)
}

/**
 * Write an ASN.1 integer.
 */
fun Asn1Encoder.WriterScope.writeInt(value: Int) {
    writeTaggedObject(Asn1Type.Integer) {
        write(value)
    }
}

/**
 * Write an ASN.1 boolean.
 */
fun Asn1Encoder.WriterScope.writeBoolean(value: Boolean) {
    writeTaggedObject(Asn1Type.Boolean) {
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
    writeTaggedObject(Asn1Type.BitString) {
        write(byteArrayOf(unusedBits.toByte()) + value)
    }
}

/**
 * Write an ASN.1 octet string.
 */
fun Asn1Encoder.WriterScope.writeOctetString(value: ByteArray) {
    writeTaggedObject(Asn1Type.OctetString) {
        write(value)
    }
}

/**
 * Write an ASN.1 utf8 string.
 */
fun Asn1Encoder.WriterScope.writeUtf8String(value: String) {
    writeTaggedObject(Asn1Type.Utf8String) {
        write(value.encodeToByteArray())
    }
}