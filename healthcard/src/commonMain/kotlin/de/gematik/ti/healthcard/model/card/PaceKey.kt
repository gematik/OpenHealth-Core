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



package de.gematik.ti.healthcard.model.card

/**
 * Pace Key for TrustedChannel with Session key for encoding and Session key for message authentication
 */
data class PaceKey(
    val enc: ByteArray,
    val mac: ByteArray,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as PaceKey

        if (!enc.contentEquals(other.enc)) return false
        if (!mac.contentEquals(other.mac)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = enc.contentHashCode()
        result = 31 * result + mac.contentHashCode()
        return result
    }
}