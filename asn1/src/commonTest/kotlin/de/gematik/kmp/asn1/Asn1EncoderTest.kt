@file:OptIn(ExperimentalStdlibApi::class)

package de.gematik.kmp.asn1

import kotlin.test.Test
import kotlin.test.assertEquals

private val hexFormat = HexFormat {
    bytes.byteSeparator = " "
    upperCase = true
}

class Asn1EncoderTest {
    @Test
    fun `write int - expected`() {
        val encoder = Asn1Encoder()
        val result = encoder.write {
            writeInt(123456)
        }
        assertEquals("02 03 01 E2 40", result.toHexString(hexFormat))
    }

    @Test
    fun `write int - zero`() {
        val encoder = Asn1Encoder()
        val result = encoder.write {
            writeInt(0)
        }
        assertEquals("02 01 00", result.toHexString(hexFormat))
    }

    @Test
    fun `write int - negative value`() {
        val encoder = Asn1Encoder()
        val result = encoder.write {
            writeInt(-123)
        }
        assertEquals("02 01 85", result.toHexString(hexFormat))
    }

    @Test
    fun `write UTF8 string - expected`() {
        val encoder = Asn1Encoder()
        val result = encoder.write {
            writeUtf8String("hello")
        }
        assertEquals("0C 05 68 65 6C 6C 6F", result.toHexString(hexFormat))
    }

    @Test
    fun `write UTF8 string - empty`() {
        val encoder = Asn1Encoder()
        val result = encoder.write {
            writeUtf8String("")
        }
        assertEquals("0C 00", result.toHexString(hexFormat))
    }

    @Test
    fun `write boolean - true`() {
        val encoder = Asn1Encoder()
        val result = encoder.write {
            writeBoolean(true)
        }
        assertEquals("01 01 FF", result.toHexString(hexFormat))
    }

    @Test
    fun `write boolean - false`() {
        val encoder = Asn1Encoder()
        val result = encoder.write {
            writeBoolean(false)
        }
        assertEquals("01 01 00", result.toHexString(hexFormat))
    }

    @Test
    fun `write with nested tags`() {
        val encoder = Asn1Encoder()
        val result = encoder.write {
            writeTaggedObject(0x30) {
                writeInt(42)
                writeUtf8String("test")
            }
        }
        assertEquals("30 09 02 01 2A 0C 04 74 65 73 74", result.toHexString(hexFormat))
    }

    @Test
    fun `write GeneralizedTime - expected`() {
        val encoder = Asn1Encoder()
        val result = encoder.write {
            writeGeneralizedTime(Asn1GeneralizedTime(2024, 11, 11, 14, 30, 15, null, null))
        }
        assertEquals("18 0F 32 30 32 34 31 31 31 31 31 34 33 30 31 35 5A", result.toHexString(hexFormat))
    }

    @Test
    fun `write GeneralizedTime - with fraction`() {
        val encoder = Asn1Encoder()
        val result = encoder.write {
            writeGeneralizedTime(Asn1GeneralizedTime(2024, 11, 11, 14, 30, 15, 500, null))
        }
        assertEquals("18 13 32 30 32 34 31 31 31 31 31 34 33 30 31 35 2E 35 30 30 5A", result.toHexString(hexFormat))
    }

    @Test
    fun `write GeneralizedTime - with offset`() {
        val encoder = Asn1Encoder()
        val result = encoder.write {
            writeGeneralizedTime(Asn1GeneralizedTime(2024, 11, 11, 14, 30, 15, null, Asn1GeneralizedTime.Offset(2, 0)))
        }
        assertEquals("18 13 32 30 32 34 31 31 31 31 31 34 33 30 31 35 2B 30 32 30 30", result.toHexString(hexFormat))
    }

    @Test
    fun `write UtcTime - expected`() {
        val encoder = Asn1Encoder()
        val result = encoder.write {
            writeUtcTime(Asn1UtcTime(24, 11, 11, 14, 30, 15, null))
        }
        assertEquals("17 0D 32 34 31 31 31 31 31 34 33 30 31 35 5A", result.toHexString(hexFormat))
    }

    @Test
    fun `write UtcTime - with offset`() {
        val encoder = Asn1Encoder()
        val result = encoder.write {
            writeUtcTime(Asn1UtcTime(24, 11, 11, 14, 30, 15, Asn1UtcTime.Offset(-5, 30)))
        }
        assertEquals("17 11 32 34 31 31 31 31 31 34 33 30 31 35 2D 30 35 33 30", result.toHexString(hexFormat))
    }
}