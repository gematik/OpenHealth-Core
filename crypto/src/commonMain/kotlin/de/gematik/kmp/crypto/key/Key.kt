package de.gematik.kmp.crypto.key

import de.gematik.kmp.crypto.ByteUnit
import de.gematik.kmp.crypto.ExperimentalCryptoApi
import de.gematik.kmp.crypto.bytes

@ExperimentalCryptoApi
interface Key {
    val data: ByteArray
}

@ExperimentalCryptoApi
class SecretKey(
    override val data: ByteArray,
) : Key {
    val length: ByteUnit = data.size.bytes
}