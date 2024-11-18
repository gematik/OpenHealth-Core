package de.gematik.kmp.crypto.exchange

import de.gematik.kmp.crypto.hexSpaceFormat
import de.gematik.kmp.crypto.key.EcCurve
import de.gematik.kmp.crypto.key.EcPrivateKey
import de.gematik.kmp.crypto.key.EcPublicKey
import de.gematik.kmp.crypto.key.decodeFromPem
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals

private const val ecPublicKey = """
-----BEGIN PUBLIC KEY-----
MFowFAYHKoZIzj0CAQYJKyQDAwIIAQEHA0IABJBhNcQG6SALcDA4AOUgfySk4E0o
LGTt+qP6dgv9qYMtojIMVQKNWfT14xR7LQnoSPABZlLJmWgh2cYKz3WbpVM=
-----END PUBLIC KEY-----
"""

private const val ecPrivateKey = """
-----BEGIN EC PRIVATE KEY-----
MIGIAgEAMBQGByqGSM49AgEGCSskAwMCCAEBBwRtMGsCAQEEIBu09g2V3coZsiK7
AUT8gHFehP7KK77g83GJH2aeYxJ1oUQDQgAEkGE1xAbpIAtwMDgA5SB/JKTgTSgs
ZO36o/p2C/2pgy2iMgxVAo1Z9PXjFHstCehI8AFmUsmZaCHZxgrPdZulUw==
-----END EC PRIVATE KEY-----
"""

class EcdhTest {
    @Test
    fun `compute secret`() =
        runTest {
            val publicKey = EcPublicKey.decodeFromPem(ecPublicKey)
            val privateKey = EcPrivateKey.decodeFromPem(ecPrivateKey)
            val result =
                EcdhSpec(EcCurve.BrainpoolP256r1)
                    .createKeyExchange(privateKey)
                    .computeSecret(publicKey)
            assertEquals(
                "A6 00 6D F4 D0 9A A6 B7 AF 41 B8 FF E6 62 78 CE B2 F6 B8 44 E1 6F 1A 73 F3 3E CB EA D3 AF 0A 7B",
                result.toHexString(hexSpaceFormat),
            )
        }
}