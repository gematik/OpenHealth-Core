package de.gematik.openhealth.smartcard.card

import kotlin.test.Test
import kotlin.test.assertEquals

class PsoAlgorithmTest {
    @Test
    fun testPsoAlgorithm() {
        val algorithm = PsoAlgorithm.SIGN_VERIFY_ECDSA
        assertEquals(0x00, algorithm.identifier)
    }

    @Test
    fun testPsoAlgorithmEntries() {
        assertEquals(1, PsoAlgorithm.entries.size)
    }
}
