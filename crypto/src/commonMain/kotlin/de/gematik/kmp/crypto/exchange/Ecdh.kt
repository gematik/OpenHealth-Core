package de.gematik.kmp.crypto.exchange

import de.gematik.kmp.crypto.ExperimentalCryptoApi
import de.gematik.kmp.crypto.key.EcCurve
import de.gematik.kmp.crypto.key.EcPrivateKey
import de.gematik.kmp.crypto.key.EcPublicKey

@ExperimentalCryptoApi
interface Ecdh {
    suspend fun computeSecret(otherPublicKey: EcPublicKey): ByteArray
}

@ExperimentalCryptoApi
class EcdhSpec(
    val curve: EcCurve,
)

@ExperimentalCryptoApi
expect fun EcdhSpec.createKeyExchange(privateKey: EcPrivateKey): Ecdh