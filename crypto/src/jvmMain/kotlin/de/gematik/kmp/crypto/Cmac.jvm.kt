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

package de.gematik.kmp.crypto

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

class JvmCmac(
    override val algorithm: CmacAlgorithm,
    secret: ByteArray,
) : Cmac {
    private var final = false

    private val algorithmName =
        when (algorithm) {
            CmacAlgorithm.Aes -> "AESCMAC"
            else -> throw IllegalArgumentException("Unknown algorithm")
        }
    private val keyName =
        when (algorithm) {
            CmacAlgorithm.Aes -> "AES"
            else -> throw IllegalArgumentException("Unknown algorithm")
        }
    private val secretKey = SecretKeySpec(secret, keyName)
    private val mac = Mac.getInstance(algorithmName, BCProvider).apply { init(secretKey) }

    override suspend fun update(data: ByteArray) {
        mac.update(data)
    }

    override suspend fun final(): ByteArray {
        if (final) throw CmacException("Final can only be called once")
        return mac.doFinal().also { final = true }
    }
}

actual fun createCmac(
    algorithm: CmacAlgorithm,
    secret: ByteArray,
): Cmac = JvmCmac(algorithm, secret)