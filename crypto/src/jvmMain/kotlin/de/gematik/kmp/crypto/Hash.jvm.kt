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

import java.security.MessageDigest

private class JvmHash(
    override val spec: HashSpec,
) : Hash {
    private var digested = false
    private val hash = MessageDigest.getInstance(spec.algorithm.name, BCProvider)

    override suspend fun update(data: ByteArray) {
        hash.update(data)
    }

    override suspend fun digest(): ByteArray {
        if (digested) throw HashException("Digest can only be called once")
        return hash.digest().also { digested = true }
    }
}

actual fun HashSpec.createHash(): Hash = JvmHash(this)