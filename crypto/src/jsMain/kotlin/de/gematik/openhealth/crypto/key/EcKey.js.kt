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

package de.gematik.openhealth.crypto.key

import de.gematik.openhealth.crypto.wrapper.runWithProvider
import de.gematik.openhealth.crypto.wrapper.toByteArray

/**
 * Returns the standardized name of the elliptic curve for use.
 * Supports Brainpool curves P256r1, P384r1, and P512r1.
 */
internal fun EcCurve.curveName() =
    when (this) {
        EcCurve.BrainpoolP256r1 -> "brainpoolP256r1"
        EcCurve.BrainpoolP384r1 -> "brainpoolP384r1"
        EcCurve.BrainpoolP512r1 -> "brainpoolP512r1"
    }

/**
 * JavaScript-specific implementation to generate an EC key pair.
 * Generates both public and private keys in ASN.1 DER format
 * and decodes them into the appropriate key types.
 */
actual fun EcKeyPairSpec.generateKeyPair(): Pair<EcPublicKey, EcPrivateKey> =
    runWithProvider {
        val keyPair = EcKeyPairGenerator.generateKeyPair(this@generateKeyPair.curve.curveName())

        EcPublicKey.decodeFromAsn1(keyPair.getPublicKeyDer().toByteArray()) to
            EcPrivateKey.decodeFromAsn1(keyPair.getPrivateKeyDer().toByteArray())
    }
