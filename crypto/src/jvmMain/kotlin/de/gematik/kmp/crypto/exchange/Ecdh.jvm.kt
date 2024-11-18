package de.gematik.kmp.crypto.exchange

import de.gematik.kmp.crypto.BCProvider
import de.gematik.kmp.crypto.ExperimentalCryptoApi
import de.gematik.kmp.crypto.key.EcPrivateKey
import de.gematik.kmp.crypto.key.EcPublicKey
import de.gematik.kmp.crypto.key.encodeToAsn1
import java.security.KeyFactory
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.KeyAgreement

private class JvmEcdh(
    val spec: EcdhSpec,
    val privateKey: EcPrivateKey,
) : Ecdh {
    private val keyAgreement: KeyAgreement =
        run {
            val keyFactory = KeyFactory.getInstance("EC", BCProvider)
            val privateKeySpec = PKCS8EncodedKeySpec(privateKey.encodeToAsn1())
            val privateKey = keyFactory.generatePrivate(privateKeySpec)

            val keyAgreement = KeyAgreement.getInstance("ECDH", BCProvider)
            keyAgreement.init(privateKey)
            keyAgreement
        }

    override suspend fun computeSecret(otherPublicKey: EcPublicKey): ByteArray {
        require(otherPublicKey.curve == spec.curve) { "Public key curve does not match spec curve" }

        val keyFactory = KeyFactory.getInstance("EC", BCProvider)
        val publicKeySpec = X509EncodedKeySpec(otherPublicKey.encodeToAsn1())
        val publicKey = keyFactory.generatePublic(publicKeySpec)
        keyAgreement.doPhase(publicKey, true)
        return keyAgreement.generateSecret()
    }
}

@ExperimentalCryptoApi
actual fun EcdhSpec.createKeyExchange(privateKey: EcPrivateKey): Ecdh = JvmEcdh(this, privateKey)