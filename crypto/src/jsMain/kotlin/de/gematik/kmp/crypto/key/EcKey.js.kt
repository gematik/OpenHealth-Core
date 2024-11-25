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

package de.gematik.kmp.crypto.key

import node.crypto.ECKeyPairDerDerOptions
import node.crypto.KeyType
import node.crypto.generateKeyPairSync
import kotlin.js.json

private fun EcCurve.curveName() =
    when (this) {
        EcCurve.BrainpoolP256r1 -> "brainpoolP256r1"
        EcCurve.BrainpoolP384r1 -> "brainpoolP384r1"
        EcCurve.BrainpoolP512r1 -> "brainpoolP512r1"
    }

actual suspend fun EcKeyPairSpec.generateKeyPair(): Pair<EcPublicKey, EcPrivateKey> {
    val options =
        json(
            "namedCurve" to this@generateKeyPair.curve.curveName(),
            "publicKeyEncoding" to
                json(
                    "type" to "spki",
                    "format" to "der",
                ),
            "privateKeyEncoding" to
                json(
                    "type" to "pkcs8",
                    "format" to "der",
                ),
        )

    @Suppress("UNCHECKED_CAST_TO_EXTERNAL_INTERFACE")
    val keyPair = generateKeyPairSync(KeyType.ec, options as ECKeyPairDerDerOptions)

    return EcPublicKey.decodeFromAsn1(keyPair.publicKey.toByteArray()) to
        EcPrivateKey.decodeFromAsn1(keyPair.privateKey.toByteArray())
}