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

import de.gematik.openhealth.crypto.BCProvider
import java.security.KeyPairGenerator
import java.security.spec.ECGenParameterSpec

private fun EcCurve.curveName() =
    when (this) {
        EcCurve.BrainpoolP256r1 -> "brainpoolP256r1"
        EcCurve.BrainpoolP384r1 -> "brainpoolP384r1"
        EcCurve.BrainpoolP512r1 -> "brainpoolP512r1"
    }

actual suspend fun EcKeyPairSpec.generateKeyPair(): Pair<EcPublicKey, EcPrivateKey> {
    val keyPairGen = KeyPairGenerator.getInstance("EC", BCProvider)
    keyPairGen.initialize(ECGenParameterSpec(curve.curveName()))
    val keyPair = keyPairGen.generateKeyPair()
    return EcPublicKey.decodeFromAsn1(keyPair.public.encoded) to
        EcPrivateKey.decodeFromAsn1(keyPair.private.encoded)
}
