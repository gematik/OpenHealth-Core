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

import de.gematik.openhealth.crypto.internal.interop.EcKeypair
import de.gematik.openhealth.crypto.wrapper.runWithProvider

internal fun EcCurve.curveName() =
    when (this) {
        EcCurve.BrainpoolP256r1 -> "brainpoolP256r1"
        EcCurve.BrainpoolP384r1 -> "brainpoolP384r1"
        EcCurve.BrainpoolP512r1 -> "brainpoolP512r1"
    }

actual fun EcKeyPairSpec.generateKeyPair(): Pair<EcPublicKey, EcPrivateKey> =
    runWithProvider {
        val keyPair = EcKeypair.generateKeypair(this@generateKeyPair.curve.curveName())

        EcPublicKey.decodeFromAsn1(keyPair.publicKeyDer.toByteArray()) to
            EcPrivateKey.decodeFromAsn1(keyPair.privateKeyDer.toByteArray())
    }
