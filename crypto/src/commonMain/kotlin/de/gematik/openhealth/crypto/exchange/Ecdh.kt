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
import de.gematik.openhealth.crypto.key.EcCurve
import de.gematik.openhealth.crypto.key.EcPrivateKey
import de.gematik.openhealth.crypto.key.EcPublicKey

/**
 * Interface for Elliptic Curve Diffie-Hellman key exchange operations.
 */
@ExperimentalCryptoApi
interface Ecdh {
    val spec: EcdhSpec

    /**
     * Computes the shared secret using the other party's public key.
     */
    fun computeSecret(otherPublicKey: EcPublicKey): ByteArray
}

/**
 * Specification for ECDH key exchange operations.
 */
@ExperimentalCryptoApi
class EcdhSpec(
    val curve: EcCurve,
)

/**
 * Creates a native ECDH key exchange instance.
 */
internal expect fun EcdhSpec.nativeCreateKeyExchange(
    scope: CryptoScope,
    privateKey: EcPrivateKey,
): Ecdh
