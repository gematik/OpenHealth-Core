package de.gematik.openhealth.smartcard.identifier

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertFailsWith

class FileIdentifierTest {
    @Test
    fun `constructor accepts valid byte array`() {
        val fid = FileIdentifier(byteArrayOf(0x3F.toByte(), 0x00))
        assertContentEquals(byteArrayOf(0x3F.toByte(), 0x00), fid.getFid())
    }

    @Test
    fun `constructor accepts valid integer`() {
        val fid = FileIdentifier(0x3F00)
        assertContentEquals(byteArrayOf(0x3F.toByte(), 0x00), fid.getFid())
    }

    @Test
    fun `constructor throws for byte array with wrong size`() {
        assertFailsWith<IllegalArgumentException> {
            FileIdentifier(byteArrayOf(0x3F.toByte()))
        }

        assertFailsWith<IllegalArgumentException> {
            FileIdentifier(byteArrayOf(0x3F.toByte(), 0x00, 0x00))
        }
    }

    @Test
    fun `constructor throws for invalid FID range below 0x1000`() {
        assertFailsWith<IllegalArgumentException> {
            FileIdentifier(0x0FFF)
        }
    }

    @Test
    fun `constructor throws for invalid FID range above 0xFEFF`() {
        assertFailsWith<IllegalArgumentException> {
            FileIdentifier(0xFF00)
        }
    }

    @Test
    fun `constructor throws for invalid FID 0x3FFF`() {
        assertFailsWith<IllegalArgumentException> {
            FileIdentifier(0x3FFF)
        }
    }

    @Test
    fun `constructor accepts special case 0x011C`() {
        val fid = FileIdentifier(0x011C)
        assertContentEquals(byteArrayOf(0x01, 0x1C), fid.getFid())
    }
}
