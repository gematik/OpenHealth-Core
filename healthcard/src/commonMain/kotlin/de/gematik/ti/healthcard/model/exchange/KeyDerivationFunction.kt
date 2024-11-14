/*
 * ${GEMATIK_COPYRIGHT_STATEMENT}
 */

package de.gematik.ti.healthcard.model.exchange

import de.gematik.kmp.crypto.ExperimentalCryptoApi
import de.gematik.kmp.crypto.HashAlgorithm
import de.gematik.kmp.crypto.createHash

private const val AES128LENGTH = 16
private const val OFFSETLENGTH = 4
private const val ENCLASTBYTE = 1
private const val MACLASTBYTE = 2
private const val PASSWORDLASTBYTE = 3

/**
 * This class provides functionality to derive AES-128 keys.
 */
object KeyDerivationFunction {
    /**
     * derive AES-128 key
     *
     * @param sharedSecretK byte array with shared secret value.
     * @param mode key derivation for ENC, MAC or derivation from password
     * @return byte array with AES-128 key
     */
    @OptIn(ExperimentalCryptoApi::class)
    suspend fun getAES128Key(sharedSecretK: ByteArray, mode: Mode): ByteArray {
        val data = replaceLastKeyByte(sharedSecretK, mode)
        val checksum = createHash(HashAlgorithm.Sha1).apply {
            update(data)
        }.digest()
        return checksum.copyOf(AES128LENGTH)
    }

    private fun replaceLastKeyByte(key: ByteArray, mode: Mode): ByteArray =
        ByteArray(key.size + OFFSETLENGTH).apply {
            key.copyInto(this)
            this[this.size - 1] = when (mode) {
                Mode.ENC -> ENCLASTBYTE.toByte()
                Mode.MAC -> MACLASTBYTE.toByte()
                Mode.PASSWORD -> PASSWORDLASTBYTE.toByte()
            }
        }

    enum class Mode {
        ENC, // key for encryption/decryption
        MAC, // key for MAC
        PASSWORD // encryption keys from a password
    }
}
