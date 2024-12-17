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

import de.gematik.openhealth.crypto.ExperimentalCryptoApi
import de.gematik.openhealth.crypto.key.EcPrivateKey

//import js.typedarrays.asInt8Array
//import node.crypto.createECDH

//private fun EcCurve.curveName() =
//    when (this) {
//        EcCurve.BrainpoolP256r1 -> "brainpoolP256r1"
//        EcCurve.BrainpoolP384r1 -> "brainpoolP384r1"
//        EcCurve.BrainpoolP512r1 -> "brainpoolP512r1"
//    }
//
//private class NodeEcdh(
//    val spec: EcdhSpec,
//    val privateKey: EcPrivateKey,
//) : Ecdh {
//    init {
//        require(spec.curve == privateKey.curve) { "Spec curve and private key curve must match." }
//    }
//
//    private val ecdh =
//        run {
//            val ecdh = createECDH(spec.curve.curveName())
//            ecdh.setPrivateKey(privateKey.data.asInt8Array())
//            ecdh
//        }
//
//    override suspend fun computeSecret(otherPublicKey: EcPublicKey): ByteArray =
//        ecdh.computeSecret(otherPublicKey.data.asInt8Array()).toByteArray()
//}

@ExperimentalCryptoApi
actual fun EcdhSpec.createKeyExchange(privateKey: EcPrivateKey): Ecdh = TODO() //NodeEcdh(this, privateKey)