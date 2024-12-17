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

package de.gematik.openhealth.crypto.key

import de.gematik.openhealth.crypto.ByteUnit
import de.gematik.openhealth.crypto.ExperimentalCryptoApi
import de.gematik.openhealth.crypto.bytes

@ExperimentalCryptoApi
interface Key {
    val data: ByteArray
}

@ExperimentalCryptoApi
class SecretKey(
    override val data: ByteArray,
) : Key {
    val length: ByteUnit = data.size.bytes

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as SecretKey

        if (!data.contentEquals(other.data)) return false
        if (length != other.length) return false

        return true
    }

    override fun hashCode(): Int {
        var result = data.contentHashCode()
        result = 31 * result + length.hashCode()
        return result
    }

    override fun toString(): String = "SecretKey(data=${data.contentToString()})"
}