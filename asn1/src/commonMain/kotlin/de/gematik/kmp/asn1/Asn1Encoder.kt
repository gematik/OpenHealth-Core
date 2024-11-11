package de.gematik.kmp.asn1

import kotlin.experimental.and

class Asn1Encoder {
    class WriterScope {
        var data = ByteArray(0)
        private set

        fun write(byte: Byte) {
            data += byte
        }

        fun write(bytes: ByteArray) {
            data += bytes
        }

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

fun Asn1Encoder.WriterScope.writeTaggedObject(tag: Int, block: Asn1Encoder.WriterScope.() -> Unit) {
    // tag
    write(tag.toByte())
    val scope = Asn1Encoder.WriterScope()
    block(scope)
    // length + value
    write(scope)
}

fun Asn1Encoder.WriterScope.writeInt(value: Int) {
    writeTaggedObject(Asn1Type.Integer) {
        write(value)
    }
}

fun Asn1Encoder.WriterScope.writeBoolean(value: Boolean) {
    writeTaggedObject(Asn1Type.Boolean) {
        write(if (value) 0xFF.toByte() else 0x00)
    }
}

fun Asn1Encoder.WriterScope.writeUtf8String(value: String) {
    writeTaggedObject(Asn1Type.Utf8String) {
        write(value.encodeToByteArray())
    }
}