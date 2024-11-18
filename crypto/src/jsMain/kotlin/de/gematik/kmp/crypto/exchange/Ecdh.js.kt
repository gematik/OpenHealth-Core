package de.gematik.kmp.crypto.exchange

import de.gematik.kmp.crypto.ExperimentalCryptoApi
import de.gematik.kmp.crypto.key.EcCurve
import de.gematik.kmp.crypto.key.EcPrivateKey
import de.gematik.kmp.crypto.key.EcPublicKey
import js.typedarrays.asInt8Array
import node.crypto.createECDH

private fun EcCurve.curveName() =
    when (this) {
        EcCurve.BrainpoolP256r1 -> "brainpoolP256r1"
        EcCurve.BrainpoolP384r1 -> "brainpoolP384r1"
        EcCurve.BrainpoolP512r1 -> "brainpoolP512r1"
    }

private class NodeEcdh(
    val spec: EcdhSpec,
    val privateKey: EcPrivateKey,
) : Ecdh {
    private val ecdh =
        run {
            val ecdh = createECDH(spec.curve.curveName())
            ecdh.setPrivateKey(privateKey.data.asInt8Array())
            ecdh
        }

    override suspend fun computeSecret(otherPublicKey: EcPublicKey): ByteArray =
        ecdh.computeSecret(otherPublicKey.data.asInt8Array()).toByteArray()
}

@ExperimentalCryptoApi
actual fun EcdhSpec.createKeyExchange(privateKey: EcPrivateKey): Ecdh = NodeEcdh(this, privateKey)