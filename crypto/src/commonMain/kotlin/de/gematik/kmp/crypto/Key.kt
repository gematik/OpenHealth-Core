package de.gematik.kmp.crypto

@ExperimentalCryptoApi
interface Key {
    val data: ByteArray
}

@ExperimentalCryptoApi
class SecretKey(override val data: ByteArray) : Key

@ExperimentalCryptoApi
interface KeyPair {
    val publicKey: Key
    val privateKey: Key
}

@ExperimentalCryptoApi
enum class EcCurve {
    BrainpoolP256r1,
    BrainpoolP384r1,
    BrainpoolP512r1;
}

@ExperimentalCryptoApi
interface EcKeyPair : KeyPair {
    val curve: EcCurve
}
//
//@ExperimentalCryptoApi
//expect fun generateEcKeyPair(curve: EcCurve): EcKeyPair
