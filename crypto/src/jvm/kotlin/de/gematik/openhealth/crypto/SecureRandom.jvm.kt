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

package de.gematik.openhealth.crypto

import de.gematik.openhealth.crypto.internal.interop.Crypto
import de.gematik.openhealth.crypto.wrapper.runWithProvider

private class JvmSecureRandom : SecureRandom() {
    override fun nextBits(bitCount: Int): Int =
        runWithProvider {
            val bytes = Crypto.cryptoRandom(bitCount / 8 + 1L).toByteArray()
            var result = 0
            for (i in bytes.indices) {
                result = result shl 8 or (bytes[i].toInt() and 0xFF)
            }
            result ushr (bytes.size * 8 - bitCount)
        }
}

/**
 * JVM-specific implementation for creating secure random number generators.
 * Creates a new secure random instance using the Web Crypto API.
 */
actual fun secureRandom(): SecureRandom = JvmSecureRandom()
