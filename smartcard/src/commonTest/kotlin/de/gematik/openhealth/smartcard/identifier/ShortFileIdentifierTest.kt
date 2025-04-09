package de.gematik.openhealth.smartcard.identifier

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class ShortFileIdentifierTest {
    @Test
    fun `constructor should throw for values below minimum`() {
        assertFailsWith<IllegalArgumentException> {
            ShortFileIdentifier(0)
        }
        assertFailsWith<IllegalArgumentException> {
            ShortFileIdentifier(-1)
        }
    }

    @Test
    fun `constructor should throw for values above maximum`() {
        assertFailsWith<IllegalArgumentException> {
            ShortFileIdentifier(31)
        }
        assertFailsWith<IllegalArgumentException> {
            ShortFileIdentifier(100)
        }
    }

    @Test
    fun `constructor should accept valid hex string values`() {
        val sfId1 = ShortFileIdentifier("01")
        assertEquals(1, sfId1.sfId)

        val sfId15 = ShortFileIdentifier("0F")
        assertEquals(15, sfId15.sfId)

        val sfId30 = ShortFileIdentifier("1E")
        assertEquals(30, sfId30.sfId)
    }

    @Test
    fun `constructor should throw for invalid hex string values`() {
        assertFailsWith<IllegalArgumentException> {
            ShortFileIdentifier("00")
        }

        assertFailsWith<IllegalArgumentException> {
            ShortFileIdentifier("1F")
        }
    }
}
