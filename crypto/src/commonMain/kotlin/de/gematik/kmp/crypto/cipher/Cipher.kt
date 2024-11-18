package de.gematik.kmp.crypto.cipher

import de.gematik.kmp.crypto.ExperimentalCryptoApi

@ExperimentalCryptoApi
interface Cipher {
    suspend fun update(data: ByteArray): ByteArray

    suspend fun final(): ByteArray
}