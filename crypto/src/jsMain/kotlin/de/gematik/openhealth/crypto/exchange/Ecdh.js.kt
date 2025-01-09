/*
 * Copyright (c) 2025 gematik GmbH
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

import de.gematik.openhealth.crypto.ExperimentalCryptoApi
import de.gematik.openhealth.crypto.key.EcCurve
import de.gematik.openhealth.crypto.key.EcPrivateKey
import de.gematik.openhealth.crypto.key.EcPublicKey
import de.gematik.openhealth.crypto.key.encodeToAsn1
import de.gematik.openhealth.crypto.wrapper.lazyWithProvider
import de.gematik.openhealth.crypto.wrapper.runWithProvider
import de.gematik.openhealth.crypto.wrapper.toByteArray
import de.gematik.openhealth.crypto.wrapper.toUint8Vector

private fun EcCurve.curveName() =
    when (this) {
        EcCurve.BrainpoolP256r1 -> "brainpoolP256r1"
        EcCurve.BrainpoolP384r1 -> "brainpoolP384r1"
        EcCurve.BrainpoolP512r1 -> "brainpoolP512r1"
    }

private class JsEcdh(
    val spec: EcdhSpec,
    val privateKey: EcPrivateKey,
) : Ecdh {
    init {
        require(spec.curve == privateKey.curve) { "Spec curve and private key curve must match." }
    }

    private val ecdh by
        lazyWithProvider {
            ECDH.create(privateKey.encodeToAsn1().toUint8Vector())
        }

    override  fun computeSecret(otherPublicKey: EcPublicKey): ByteArray =
        runWithProvider {
            ecdh.computeSecret(otherPublicKey.encodeToAsn1().toUint8Vector()).toByteArray()
        }
}

@ExperimentalCryptoApi
actual fun EcdhSpec.createKeyExchange(privateKey: EcPrivateKey): Ecdh = JsEcdh(this, privateKey)