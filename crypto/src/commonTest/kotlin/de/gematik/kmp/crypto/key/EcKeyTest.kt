package de.gematik.kmp.crypto.key

import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals

class EcKeyTest {
    @Test
    fun `encode and decode ec public key from pem`() {
        val ecPublicKey =
            EcPublicKey.fromUncompressedFormat(
                EcCurve.BrainpoolP256r1,
                byteArrayOf(0x04) + Random.nextBytes(32) + Random.nextBytes(32),
            )
        val ecPublicKeyResult = EcPublicKey.decodeFromAsn1(ecPublicKey.encodeToAsn1())

        assertEquals(ecPublicKey, ecPublicKeyResult)
    }

    @Test
    fun `encode and decode ec private key from pem`() {
        val ecPrivateKey = EcPrivateKey.fromScalar(EcCurve.BrainpoolP256r1, Random.nextBytes(32))
        val ecPrivateKeyResult = EcPrivateKey.decodeFromAsn1(ecPrivateKey.encodeToAsn1())

        assertEquals(ecPrivateKey, ecPrivateKeyResult)
    }
}