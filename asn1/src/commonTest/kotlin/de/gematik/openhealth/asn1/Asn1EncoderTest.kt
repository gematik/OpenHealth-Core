/*
 * Copyright (c) 2025 gematik GmbH
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

@file:OptIn(ExperimentalStdlibApi::class)

package de.gematik.openhealth.asn1

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertFailsWith

private val hexFormat =
    HexFormat {
        bytes.byteSeparator = " "
        upperCase = true
    }

class Asn1EncoderTest {
    @Test
    fun `write multi-byte tag - small value`() {
        val encoder = Asn1Encoder()
        val result =
            encoder.write {
                writeTaggedObject(33, Asn1Tag.APPLICATION) {
                    write(0x05)
                }
            }
        assertEquals("5F 21 01 05", result.toHexString(hexFormat))
    }

    @Test
    fun `write multi-byte tag - larger value`() {
        val encoder = Asn1Encoder()
        val result =
            encoder.write {
                writeTaggedObject(128, Asn1Tag.APPLICATION) {
                    write(0x05)
                }
            }
        assertEquals("5F 81 00 01 05", result.toHexString(hexFormat))
    }

    @Test
    fun `write multi-byte tag - very large value`() {
        val encoder = Asn1Encoder()
        val result =
            encoder.write {
                writeTaggedObject(16384, Asn1Tag.APPLICATION) {
                    write(0x05)
                }
            }
        assertEquals("5F 81 80 00 01 05", result.toHexString(hexFormat))
    }

    @Test
    fun `write multi-byte tag - maximum single-byte tag`() {
        val encoder = Asn1Encoder()
        val result =
            encoder.write {
                writeTaggedObject(30, Asn1Tag.APPLICATION) {
                    write(0x05)
                }
            }
        assertEquals("5E 01 05", result.toHexString(hexFormat))
    }

    @Test
    fun `write multi-byte length`() {
        val encoder = Asn1Encoder()
        val result =
            encoder.write {
                writeLength(123456789)
            }
        assertEquals("84 07 5B CD 15", result.toHexString(hexFormat))
    }

    @Test
    fun `write multi-byte length - negative value`() {
        val encoder = Asn1Encoder()
        assertFails {
            encoder.write {
                writeLength(-123456789)
            }
        }
    }

    @Test
    fun `write int - expected`() {
        val encoder = Asn1Encoder()
        val result =
            encoder.write {
                writeInt(123456)
            }
        assertEquals("02 03 01 E2 40", result.toHexString(hexFormat))
    }

    @Test
    fun `write int - zero`() {
        val encoder = Asn1Encoder()
        val result =
            encoder.write {
                writeInt(0)
            }
        assertEquals("02 01 00", result.toHexString(hexFormat))
    }

    @Test
    fun `write int - negative value`() {
        val encoder = Asn1Encoder()
        val result =
            encoder.write {
                writeInt(-123)
            }
        assertEquals("02 01 85", result.toHexString(hexFormat))
    }

    @Test
    fun `write UTF8 string - expected`() {
        val encoder = Asn1Encoder()
        val result =
            encoder.write {
                writeUtf8String("hello")
            }
        assertEquals("0C 05 68 65 6C 6C 6F", result.toHexString(hexFormat))
    }

    @Test
    fun `write UTF8 string - empty`() {
        val encoder = Asn1Encoder()
        val result =
            encoder.write {
                writeUtf8String("")
            }
        assertEquals("0C 00", result.toHexString(hexFormat))
    }

    @Test
    fun `write boolean - true`() {
        val encoder = Asn1Encoder()
        val result =
            encoder.write {
                writeBoolean(true)
            }
        assertEquals("01 01 FF", result.toHexString(hexFormat))
    }

    @Test
    fun `write boolean - false`() {
        val encoder = Asn1Encoder()
        val result =
            encoder.write {
                writeBoolean(false)
            }
        assertEquals("01 01 00", result.toHexString(hexFormat))
    }

    @Test
    fun `write with nested tags`() {
        val encoder = Asn1Encoder()
        val result =
            encoder.write {
                writeTaggedObject(0x10, Asn1Tag.CONSTRUCTED) {
                    writeInt(42)
                    writeUtf8String("test")
                }
            }
        assertEquals("30 09 02 01 2A 0C 04 74 65 73 74", result.toHexString(hexFormat))
    }

    @Test
    fun `write OID - simple`() {
        val encoder = Asn1Encoder()
        val result =
            encoder.write {
                writeObjectIdentifier("1.2.840.113549")
            }
        assertEquals("06 06 2A 86 48 86 F7 0D", result.toHexString(hexFormat))
    }

    @Test
    fun `write OID - single part beyond 40`() {
        val encoder = Asn1Encoder()
        val result =
            encoder.write {
                writeObjectIdentifier("2.100.3")
            }
        assertEquals("06 03 81 34 03", result.toHexString(hexFormat))
    }

    @Test
    fun `write OID - long identifier`() {
        val encoder = Asn1Encoder()
        val result =
            encoder.write {
                writeObjectIdentifier("1.2.3.4.5.265566")
            }
        assertEquals("06 07 2A 03 04 05 90 9A 5E", result.toHexString(hexFormat))
    }

    @Test
    fun `write OID - large first component`() {
        val encoder = Asn1Encoder()
        val result =
            encoder.write {
                writeObjectIdentifier("2.999.1")
            }
        assertEquals("06 03 88 37 01", result.toHexString(hexFormat))
    }

    @Test
    fun `write OID - invalid first part`() {
        val encoder = Asn1Encoder()
        assertFailsWith<Asn1EncoderException> {
            encoder.write {
                writeObjectIdentifier("3.1.2")
            }
        }
    }

    @Test
    fun `write OID - invalid encoding`() {
        val encoder = Asn1Encoder()
        assertFailsWith<Asn1EncoderException> {
            encoder.write {
                writeObjectIdentifier("1.40.1")
            }
        }
    }

    @Test
    fun `write GeneralizedTime - expected`() {
        val encoder = Asn1Encoder()
        val result =
            encoder.write {
                writeGeneralizedTime(Asn1GeneralizedTime(2024, 11, 11, 14, 30, 15, null, null))
            }
        assertEquals(
            "18 0F 32 30 32 34 31 31 31 31 31 34 33 30 31 35 5A",
            result.toHexString(hexFormat),
        )
    }

    @Test
    fun `write GeneralizedTime - with fraction`() {
        val encoder = Asn1Encoder()
        val result =
            encoder.write {
                writeGeneralizedTime(Asn1GeneralizedTime(2024, 11, 11, 14, 30, 15, 500, null))
            }
        assertEquals(
            "18 13 32 30 32 34 31 31 31 31 31 34 33 30 31 35 2E 35 30 30 5A",
            result.toHexString(hexFormat),
        )
    }

    @Test
    fun `write GeneralizedTime - with offset`() {
        val encoder = Asn1Encoder()
        val result =
            encoder.write {
                writeGeneralizedTime(
                    Asn1GeneralizedTime(
                        2024,
                        11,
                        11,
                        14,
                        30,
                        15,
                        null,
                        Asn1GeneralizedTime.Offset(2, 0),
                    ),
                )
            }
        assertEquals(
            "18 13 32 30 32 34 31 31 31 31 31 34 33 30 31 35 2B 30 32 30 30",
            result.toHexString(hexFormat),
        )
    }

    @Test
    fun `write UtcTime - expected`() {
        val encoder = Asn1Encoder()
        val result =
            encoder.write {
                writeUtcTime(Asn1UtcTime(24, 11, 11, 14, 30, 15, null))
            }
        assertEquals("17 0D 32 34 31 31 31 31 31 34 33 30 31 35 5A", result.toHexString(hexFormat))
    }

    @Test
    fun `write UtcTime - with offset`() {
        val encoder = Asn1Encoder()
        val result =
            encoder.write {
                writeUtcTime(Asn1UtcTime(24, 11, 11, 14, 30, 15, Asn1UtcTime.Offset(-5, 30)))
            }
        assertEquals(
            "17 11 32 34 31 31 31 31 31 34 33 30 31 35 2D 30 35 33 30",
            result.toHexString(hexFormat),
        )
    }
}