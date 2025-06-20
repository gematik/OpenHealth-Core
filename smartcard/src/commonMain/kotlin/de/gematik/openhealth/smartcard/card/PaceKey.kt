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

package de.gematik.openhealth.smartcard.card

import de.gematik.openhealth.crypto.ExperimentalCryptoApi
import de.gematik.openhealth.crypto.HashAlgorithm
import de.gematik.openhealth.crypto.HashSpec
import de.gematik.openhealth.crypto.key.SecretKey
import de.gematik.openhealth.crypto.useCrypto
import kotlin.js.JsExport

/**
 * Pace Key for TrustedChannel with Session key for encoding and Session key for message authentication
 */
@JsExport
@OptIn(ExperimentalCryptoApi::class)
class PaceKey(
    val enc: SecretKey,
    val mac: SecretKey,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as PaceKey

        if (!enc.equals(other.enc)) return false
        if (!mac.equals(other.mac)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = enc.hashCode()
        result = 31 * result + mac.hashCode()
        return result
    }
}

private const val AES128_LENGTH = 16
private const val OFFSET_LENGTH = 4
private const val ENCLASTBYTE = 1
private const val MACLASTBYTE = 2
private const val PASSWORDLASTBYTE = 3

/**
 * Derive AES-128 key
 *
 * @param sharedSecretK byte array with shared secret value.
 * @param mode key derivation for ENC, MAC or derivation from password
 * @return byte array with AES-128 key
 */
@OptIn(ExperimentalCryptoApi::class)
fun getAES128Key(
    sharedSecretK: ByteArray,
    mode: Mode,
): ByteArray {
    require(sharedSecretK.isNotEmpty()) { "Shared secret cannot be empty" }
    val modifiedKey = appendModeByte(sharedSecretK, mode)

    val checksum =
        useCrypto {
            HashSpec(HashAlgorithm.Sha1).createHash().let {
                it.update(modifiedKey)
                it.digest()
            }
        }
    return checksum.copyOf(AES128_LENGTH)
}

/**
 * Append the mode-specific byte to the shared secret.
 *
 * @param key The original shared secret
 * @param mode The mode (ENC, MAC, or PASSWORD)
 * @return Modified key with mode byte appended
 */
private fun appendModeByte(
    key: ByteArray,
    mode: Mode,
): ByteArray {
    val modeByte =
        when (mode) {
            Mode.ENC -> ENCLASTBYTE.toByte()
            Mode.MAC -> MACLASTBYTE.toByte()
            Mode.PASSWORD -> PASSWORDLASTBYTE.toByte()
        }
    return ByteArray(key.size + OFFSET_LENGTH).apply {
        key.copyInto(this, 0, 0, key.size)
        this[this.size - 1] = modeByte
    }
}

/**
 * Mode for key derivation
 *
 * @property ENC Key for encryption/decryption
 * @property MAC Key for MAC
 * @property PASSWORD Key derived from password
 */
enum class Mode {
    ENC,
    MAC,
    PASSWORD,
}
