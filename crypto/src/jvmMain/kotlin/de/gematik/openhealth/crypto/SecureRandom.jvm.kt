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


private class JvmSecureRandom : SecureRandom() {
    private val secureRandom = java.security.SecureRandom()

    override fun nextBits(bitCount: Int): Int {
        val bytes = ByteArray((bitCount + 7) / 8)
        secureRandom.nextBytes(bytes)
        var result = 0
        for (i in bytes.indices) {
            result = result shl 8 or (bytes[i].toInt() and 0xFF)
        }
        return result ushr (bytes.size * 8 - bitCount)
    }
}

actual fun secureRandom(): SecureRandom = JvmSecureRandom()