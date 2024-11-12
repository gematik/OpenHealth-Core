@file:OptIn(ExperimentalStdlibApi::class)

package de.gematik.kmp.crypto

import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

private val hexFormat = HexFormat {
    bytes.byteSeparator = " "
    upperCase = true
}

class HashTest {

    @Test
    fun `hash with valid data - expected`()= runTest {
        val hash = createHash(HashAlgorithm.Sha1)
        hash.update("Hello, World!".encodeToByteArray())
        val result = hash.digest()
        assertEquals("0A 0A 9F 2A 67 72 94 25 57 AB 53 55 D7 6A F4 42 F8 F6 5E 01", result.toHexString(hexFormat))
    }

    @Test
    fun `hash with empty data`()= runTest {
        val hash = createHash(HashAlgorithm.Sha1)
        hash.update(ByteArray(0))
        val result = hash.digest()
        assertEquals("DA 39 A3 EE 5E 6B 4B 0D 32 55 BF EF 95 60 18 90 AF D8 07 09", result.toHexString(hexFormat))
    }

    @Test
    fun `hash with multiple updates`()= runTest {
        val hash = createHash(HashAlgorithm.Sha1)
        hash.update("Hello, ".encodeToByteArray())
        hash.update("World!".encodeToByteArray())
        val result = hash.digest()
        assertEquals("0A 0A 9F 2A 67 72 94 25 57 AB 53 55 D7 6A F4 42 F8 F6 5E 01", result.toHexString(hexFormat))
    }

    @Test
    fun `digest can only be called once`()= runTest {
        val hash = createHash(HashAlgorithm.Sha1)
        hash.update("Test data".encodeToByteArray())
        hash.digest()
        assertFailsWith<HashException> {
            hash.digest()
        }
    }
}
