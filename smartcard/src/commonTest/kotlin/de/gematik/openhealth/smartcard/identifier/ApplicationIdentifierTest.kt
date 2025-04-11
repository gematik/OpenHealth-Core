package de.gematik.openhealth.smartcard.identifier

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotSame

class ApplicationIdentifierTest {
    @Test
    fun `constructor should accept valid byte array`() {
        val minAid = byteArrayOf(0x01, 0x02, 0x03, 0x04, 0x05)
        val aidMin = ApplicationIdentifier(minAid)
        assertContentEquals(minAid, aidMin.aid)

        val maxAid = ByteArray(16) { it.toByte() }
        val aidMax = ApplicationIdentifier(maxAid)
        assertContentEquals(maxAid, aidMax.aid)
    }

    @Test
    fun `constructor should throw for too short byte array`() {
        assertFailsWith<IllegalArgumentException> {
            ApplicationIdentifier(byteArrayOf(0x01, 0x02, 0x03, 0x04))
        }
    }

    @Test
    fun `constructor should throw for too long byte array`() {
        assertFailsWith<IllegalArgumentException> {
            ApplicationIdentifier(ByteArray(17) { it.toByte() })
        }
    }

    @Test
    fun `constructor should accept valid hex string`() {
        val aid = ApplicationIdentifier("0102030405")
        assertContentEquals(byteArrayOf(0x01, 0x02, 0x03, 0x04, 0x05), aid.aid)
    }

    @Test
    fun `constructor should throw for invalid hex string length`() {
        assertFailsWith<IllegalArgumentException> {
            ApplicationIdentifier("01020304") // Too short
        }
        assertFailsWith<IllegalArgumentException> {
            ApplicationIdentifier("0102030405060708091011121314151617") // Too long
        }
    }

    @Test
    fun `getter should return defensive copy`() {
        val originalAid = byteArrayOf(0x01, 0x02, 0x03, 0x04, 0x05)
        val aid = ApplicationIdentifier(originalAid)

        // Verify that modifying the original array doesn't affect the AID
        originalAid[0] = 0xFF.toByte()
        assertContentEquals(byteArrayOf(0x01, 0x02, 0x03, 0x04, 0x05), aid.aid)

        // Verify that modifying the returned array doesn't affect the AID
        val returnedAid = aid.aid
        returnedAid[0] = 0xFF.toByte()
        assertContentEquals(byteArrayOf(0x01, 0x02, 0x03, 0x04, 0x05), aid.aid)

        // Verify that each getter call returns a new array
        assertNotSame(aid.aid, aid.aid)
    }
}
