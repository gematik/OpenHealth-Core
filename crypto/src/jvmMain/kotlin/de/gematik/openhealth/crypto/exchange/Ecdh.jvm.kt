/*
 * Copyright (c) 2024 gematik GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package de.gematik.openhealth.crypto.exchange

import de.gematik.openhealth.crypto.BCProvider
import de.gematik.openhealth.crypto.ExperimentalCryptoApi
import de.gematik.openhealth.crypto.key.EcPrivateKey
import de.gematik.openhealth.crypto.key.EcPublicKey
import de.gematik.openhealth.crypto.key.encodeToAsn1
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
