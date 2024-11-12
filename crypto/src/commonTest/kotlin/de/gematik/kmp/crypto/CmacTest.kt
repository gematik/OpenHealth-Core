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

class CmacTest {

    val secret = "67 AD A7 BE 54 75 0C 47 44 D0 E3 46 66 33 64 05".hexToByteArray(hexFormat)

        @Test
        fun `cmac with valid data - expected`() = runTest {
            val cmac = createCmac(CmacAlgorithm.Aes, secret)
            cmac.update("Hello, World!".encodeToByteArray())
            val result = cmac.final()
            assertEquals("6B 77 96 A8 0D E9 BB C2 0A B3 E9 95 96 DF EF 43", result.toHexString(hexFormat))
        }

        @Test
        fun `cmac with empty data`() = runTest {
            val cmac = createCmac(CmacAlgorithm.Aes, secret)
            cmac.update(ByteArray(0))
            val result = cmac.final()
            assertEquals("4F 26 7F 72 08 20 4D 86 B1 AB A8 5A 4C 40 51 E5", result.toHexString(hexFormat))
        }

        @Test
        fun `cmac with multiple updates`() = runTest {
            val cmac = createCmac(CmacAlgorithm.Aes, secret)
            cmac.update("Hello, ".encodeToByteArray())
            cmac.update("World!".encodeToByteArray())
            val result = cmac.final()
            assertEquals("6B 77 96 A8 0D E9 BB C2 0A B3 E9 95 96 DF EF 43", result.toHexString(hexFormat))
        }

        @Test
        fun `cmac final can only be called once`() = runTest {
            val cmac = createCmac(CmacAlgorithm.Aes, secret)
            cmac.update("Test data".encodeToByteArray())
            cmac.final()
            assertFailsWith<CmacException> {
                cmac.final()
            }
        }
}