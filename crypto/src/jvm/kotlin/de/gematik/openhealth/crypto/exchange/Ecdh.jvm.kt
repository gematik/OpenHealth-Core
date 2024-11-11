/*
 * Copyright 2025 gematik GmbH
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

import de.gematik.openhealth.crypto.CryptoScope
import de.gematik.openhealth.crypto.ExperimentalCryptoApi
import de.gematik.openhealth.crypto.key.EcPrivateKey
import de.gematik.openhealth.crypto.key.EcPublicKey
import de.gematik.openhealth.crypto.key.encodeToAsn1
import de.gematik.openhealth.crypto.wrapper.DeferScope
import de.gematik.openhealth.crypto.wrapper.deferred
import de.gematik.openhealth.crypto.wrapper.lazyDeferred
import de.gematik.openhealth.crypto.wrapper.runWithProvider
import de.gematik.openhealth.crypto.wrapper.toUint8Vector
import de.gematik.openhealth.crypto.internal.interop.Ecdh as JniEcdh

private class JvmEcdh(
    override val spec: EcdhSpec,
    private val privateKey: EcPrivateKey,
    scope: CryptoScope,
) : Ecdh,
    DeferScope by deferred(scope) {
    init {
        require(spec.curve == privateKey.curve) { "Spec curve and private key curve must match." }
    }

    private val ecdh by
        lazyDeferred {
            JniEcdh.create(privateKey.encodeToAsn1().toUint8Vector().alsoDefer())
        }

    override fun computeSecret(otherPublicKey: EcPublicKey): ByteArray =
        runWithProvider {
            ecdh
                .computeSecret(
                    otherPublicKey.encodeToAsn1().toUint8Vector().alsoDefer(),
                ).toByteArray()
        }
}

/**
 * JVM-specific implementation for creating ECDH key exchange instances.
 */
@ExperimentalCryptoApi
internal actual fun EcdhSpec.nativeCreateKeyExchange(
    scope: CryptoScope,
    privateKey: EcPrivateKey,
): Ecdh = JvmEcdh(this, privateKey, scope)
