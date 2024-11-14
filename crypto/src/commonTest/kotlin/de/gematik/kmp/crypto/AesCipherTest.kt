@file:OptIn(ExperimentalStdlibApi::class)

package de.gematik.kmp.crypto

import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals

private val hexFormat = HexFormat {
    bytes.byteSeparator = " "
    upperCase = true
}

class AesCipherTest {
    @Test
    fun `aes ecb - 128 bit encryption`() = runTest {
        val cipher = createAesEcbCipher(16, SecretKey("1234567890123456".encodeToByteArray()))
        cipher.update("Hello World".encodeToByteArray())
        val result = cipher.final()
        assertEquals("C5 00 17 56 2E 76 83 EC 13 EF 1A 15 37 4F 2C B1", result.toHexString(hexFormat))
    }

    @Test
    fun `aes ecb - 128 bit decryption`() = runTest {
        val cipher = createAesEcbDecipher(16, SecretKey("1234567890123456".encodeToByteArray()))
        cipher.update("C5 00 17 56 2E 76 83 EC 13 EF 1A 15 37 4F 2C B1".hexToByteArray(hexFormat))
        val result = cipher.final()
        assertEquals("Hello World", result.decodeToString())
    }

    @Test
    fun `aes gcm - 128 bit encryption`() = runTest {
        val cipher = createAesEcbCipher(16, SecretKey("1234567890123456".encodeToByteArray()))
        cipher.update("Hello World".encodeToByteArray())
        val result = cipher.final()
        assertEquals("C5 00 17 56 2E 76 83 EC 13 EF 1A 15 37 4F 2C B1", result.toHexString(hexFormat))
    }

    @Test
    fun `aes gcm - 128 bit decryption`() = runTest {
        val cipher = createAesEcbDecipher(16, SecretKey("1234567890123456".encodeToByteArray()))
        cipher.update("C5 00 17 56 2E 76 83 EC 13 EF 1A 15 37 4F 2C B1".hexToByteArray(hexFormat))
        val result = cipher.final()
        assertEquals("Hello World", result.decodeToString())
    }
}