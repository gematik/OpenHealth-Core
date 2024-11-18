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

package de.gematik.kmp.asn1

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

private val hexFormat =
    HexFormat {
        bytes.byteSeparator = " "
        upperCase = true
    }

class Asn1DecoderTest {
    @Test
    fun `advance with tag`() {
        val parser = Asn1Decoder("30 0A 04 03 66 6F 6F 04 03 62 61 72".hexToByteArray(hexFormat))
        val result =
            parser.read {
                advanceWithTag(0x30) {
                    buildList {
                        advanceWithTag(0x04) { add(readBytes(3).decodeToString()) }
                        advanceWithTag(0x04) { add(readBytes(3).decodeToString()) }
                    }
                }
            }
        assertEquals(listOf("foo", "bar"), result)
    }

    @Test
    fun `advance with tag - infinite length`() {
        val parser =
            Asn1Decoder("30 80 04 03 66 6F 6F 04 03 62 61 72 00 00".hexToByteArray(hexFormat))
        val result =
            parser.read {
                advanceWithTag(0x30) {
                    buildList {
                        advanceWithTag(0x04) { add(readBytes(3).decodeToString()) }
                        advanceWithTag(0x04) { add(readBytes(3).decodeToString()) }
                    }
                }
            }
        assertEquals(listOf("foo", "bar"), result)
    }

    @Test
    fun `advance with tag - unfinished parsing`() {
        val parser =
            Asn1Decoder("30 80 04 03 66 6F 6F 04 03 62 61 72 00 00".hexToByteArray(hexFormat))
        assertFailsWith<Asn1DecoderException> {
            parser.read {
                advanceWithTag(0x30) {
                    advanceWithTag(0x04) { readBytes(3) }
                }
            }
        }
    }

    @Test
    fun `advance with tag - skip infinite`() {
        val parser =
            Asn1Decoder("30 80 04 03 66 6F 6F 04 03 62 61 72 00 00".hexToByteArray(hexFormat))
        assertFailsWith<Asn1DecoderException> {
            parser.read {
                advanceWithTag(0x30) {
                    advanceWithTag(0x04) { readBytes(3) }
                    skipToEnd()
                }
            }
        }
    }

    @Test
    fun `read boolean true`() {
        val parser = Asn1Decoder("01 01 FF".hexToByteArray(hexFormat))
        val result =
            parser.read {
                readBoolean()
            }
        assertTrue(result)
    }

    @Test
    fun `read boolean false`() {
        val parser = Asn1Decoder("01 01 00".hexToByteArray(hexFormat))
        val result =
            parser.read {
                readBoolean()
            }
        assertFalse(result)
    }

    @Test
    fun `read integer`() {
        val parser = Asn1Decoder("02 01 7F".hexToByteArray(hexFormat))
        val result =
            parser.read {
                readInt()
            }
        assertEquals(127, result)
    }

    @Test
    fun `read integer - negative number`() {
        val parser = Asn1Decoder("02 01 EC".hexToByteArray(hexFormat))
        val result =
            parser.read {
                readInt()
            }
        assertEquals(-20, result)
    }

    @Test
    fun `read integer - boundary case`() {
        val parser = Asn1Decoder("02 01 80".hexToByteArray(hexFormat))
        val result =
            parser.read {
                readInt()
            }
        assertEquals(-128, result)
    }

    @Test
    fun `read integer - multi-byte length`() {
        val parser = Asn1Decoder("02 02 7F 7F".hexToByteArray(hexFormat))
        val result =
            parser.read {
                readInt()
            }
        assertEquals(32639, result) // Expected result for 0x7F7F
    }

    @Test
    fun `read bit string - no unused bits`() {
        val parser = Asn1Decoder("03 05 00 FF AA BB CC".hexToByteArray(hexFormat))
        val result = parser.read { readBitString() }.toHexString(hexFormat)
        assertEquals("FF AA BB CC", result)
    }

    @Test
    fun `read bit string - with unused bits`() {
        val parser = Asn1Decoder("03 05 03 FF AA BB FF".hexToByteArray(hexFormat)) // Last 3 bits unused
        val result = parser.read { readBitString() }.toHexString(hexFormat)
        assertEquals("FF AA BB F8", result) // FF with last 3 bits unused becomes F8
    }

    @Test
    fun `read bit string - empty bit string`() {
        val parser = Asn1Decoder("03 01 00".hexToByteArray(hexFormat)) // No bits, only unused bits byte
        val result = parser.read { readBitString() }.toHexString(hexFormat)
        assertEquals("", result)
    }

    @Test
    fun `read bit string - invalid unused bits`() {
        val parser = Asn1Decoder("03 04 08 FF AA BB CC".hexToByteArray(hexFormat)) // Invalid unused bits > 7
        assertFailsWith<Asn1DecoderException> {
            parser.read { readBitString() }
        }
    }

    @Test
    fun `read bit string - correct parsing within complex structure`() {
        val parser =
            Asn1Decoder("30 0C 03 04 00 FF AA BB 03 04 01 CC DD 00".hexToByteArray(hexFormat))
        val result =
            parser.read {
                advanceWithTag(0x30) {
                    buildList {
                        add(readBitString().toHexString(hexFormat)) // First BIT STRING
                        add(readBitString().toHexString(hexFormat)) // Second BIT STRING
                    }
                }
            }
        assertEquals(listOf("FF AA BB", "CC DD 00"), result)
    }

    @Test
    fun `read utf8 string`() {
        val parser = Asn1Decoder("04 05 48 65 6C 6C 6F".hexToByteArray(hexFormat))
        val result =
            parser.read {
                readUtf8String()
            }
        assertEquals("Hello", result)
    }

    @Test
    fun `read utf8 string - empty`() {
        val parser = Asn1Decoder("04 00".hexToByteArray(hexFormat))
        val result =
            parser.read {
                readUtf8String()
            }
        assertEquals("", result)
    }

    @Test
    fun `read utf8 string - invalid data`() {
        val parser = Asn1Decoder("04 03 C3 28".hexToByteArray(hexFormat)) // Invalid UTF-8 sequence
        assertFailsWith<Asn1DecoderException> {
            parser.read { readUtf8String() }
        }
    }

    @Test
    fun `read visible string`() {
        val parser = Asn1Decoder("1A 05 57 6F 72 6C 64".hexToByteArray(hexFormat))
        val result =
            parser.read {
                readVisibleString()
            }
        assertEquals("World", result)
    }

    @Test
    fun `read visible string - special characters`() {
        val parser = Asn1Decoder("1A 06 41 42 20 21 40 23".hexToByteArray(hexFormat)) // Includes ASCII space and symbols
        val result =
            parser.read {
                readVisibleString()
            }
        assertEquals("AB !@#", result)
    }

    @Test
    fun `read utc time`() {
        val parser =
            Asn1Decoder("17 0D 32 33 30 35 31 32 31 34 33 39 34 35 5A".hexToByteArray(hexFormat))
        val result =
            parser.read {
                readUtcTime()
            }
        assertEquals(Asn1UtcTime(23, 5, 12, 14, 39, 45, null), result)
    }

    @Test
    fun `read utc time - negative offset`() {
        val parser =
            Asn1Decoder(
                "17 11 32 33 30 35 31 32 31 34 33 39 34 35 2D 30 35 30 30".hexToByteArray(
                    hexFormat,
                ),
            )
        val result =
            parser.read {
                readUtcTime()
            }
        assertEquals(Asn1UtcTime(23, 5, 12, 14, 39, 45, Asn1UtcTime.Offset(-5, 0)), result)
    }

    @Test
    fun `read utc time - missing seconds`() {
        val parser = Asn1Decoder("17 0B 32 33 30 35 31 32 31 34 33 39 5A".hexToByteArray(hexFormat))
        val result =
            parser.read {
                readUtcTime()
            }
        assertEquals(Asn1UtcTime(23, 5, 12, 14, 39, null, null), result)
    }

    @Test
    fun `read generalized time`() {
        val parser =
            Asn1Decoder(
                "18 12 32 30 32 33 30 35 31 32 31 34 33 39 34 35 2E 31 32 33 5A".hexToByteArray(
                    hexFormat,
                ),
            )
        val result =
            parser.read {
                readGeneralizedTime()
            }
        assertEquals(Asn1GeneralizedTime(2023, 5, 12, 14, 39, 45, 123, null), result)
    }

    @Test
    fun `read generalized time - no fraction`() {
        val parser =
            Asn1Decoder("18 0D 32 30 32 33 30 35 31 32 31 34 33 39 5A".hexToByteArray(hexFormat))
        val result =
            parser.read {
                readGeneralizedTime()
            }
        assertEquals(Asn1GeneralizedTime(2023, 5, 12, 14, 39, null, null, null), result)
    }

    @Test
    fun `read valid simple oid`() {
        val parser = Asn1Decoder("06 03 2A 03 04".hexToByteArray(hexFormat))
        val result =
            parser.read {
                readObjectIdentifier()
            }
        assertEquals("1.2.3.4", result)
    }

    @Test
    fun `read valid complex oid`() {
        val parser = Asn1Decoder("06 05 55 04 06 82 03".hexToByteArray(hexFormat))
        val result =
            parser.read {
                readObjectIdentifier()
            }
        assertEquals("2.5.4.6.259", result)
    }

    @Test
    fun `read empty oid - throws exception`() {
        val parser = Asn1Decoder("06 00".hexToByteArray(hexFormat))
        assertFailsWith<Asn1DecoderException> {
            parser.read {
                readObjectIdentifier()
            }
        }
    }

    @Test
    fun `read single-byte oid`() {
        val parser = Asn1Decoder("06 01 06".hexToByteArray(hexFormat))
        val result =
            parser.read {
                readObjectIdentifier()
            }
        assertEquals("0.6", result)
    }

    @Test
    fun `read oid with high-value bytes`() {
        val parser = Asn1Decoder("06 03 82 86 05".hexToByteArray(hexFormat))
        val result =
            parser.read {
                readObjectIdentifier()
            }
        assertEquals("3.10.773", result)
    }

    @Test
    fun `read oid with overflow in intermediate value`() {
        val parser = Asn1Decoder("06 04 2B 81 80 02".hexToByteArray(hexFormat))
        val result =
            parser.read {
                readObjectIdentifier()
            }
        assertEquals("1.3.16386", result)
    }

    @Test
    fun `read oid with trailing continuation bit throws exception`() {
        val parser = Asn1Decoder("06 02 2B 81".hexToByteArray(hexFormat))
        assertFailsWith<Asn1DecoderException> {
            parser.read {
                readObjectIdentifier()
            }
        }
    }
}