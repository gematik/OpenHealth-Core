package de.gematik.kmp.crypto.key

import de.gematik.kmp.asn1.Asn1Decoder
import de.gematik.kmp.asn1.Asn1Encoder
import de.gematik.kmp.asn1.Asn1Type
import de.gematik.kmp.asn1.readBitString
import de.gematik.kmp.asn1.readInt
import de.gematik.kmp.asn1.readObjectIdentifier
import de.gematik.kmp.asn1.readOctetString
import de.gematik.kmp.asn1.toConstructedTag
import de.gematik.kmp.asn1.writeBitString
import de.gematik.kmp.asn1.writeInt
import de.gematik.kmp.asn1.writeObjectIdentifier
import de.gematik.kmp.asn1.writeOctetString
import de.gematik.kmp.asn1.writeTaggedObject
import de.gematik.kmp.crypto.ExperimentalCryptoApi
import de.gematik.kmp.crypto.Pem
import de.gematik.kmp.crypto.decodeToPem
import de.gematik.kmp.crypto.encodeToString
import de.gematik.kmp.crypto.key.EcPrivateKey.Companion

@ExperimentalCryptoApi
enum class EcCurve(
    val oid: String,
) {
    BrainpoolP256r1("1.3.36.3.3.2.8.1.1.7"),
    BrainpoolP384r1("1.3.36.3.3.2.8.1.1.11"),
    BrainpoolP512r1("1.3.36.3.3.2.8.1.1.13"),
}

// @ExperimentalCryptoApi
// expect suspend fun EcCurve.generateKeyPair(): EcPublicKey
//
// @ExperimentalCryptoApi
// expect suspend fun EcCurve.generateKeyPair(): Pair<EcPublicKey, EcPrivateKey>

@ExperimentalCryptoApi
class EcPublicKey internal constructor(
    val curve: EcCurve,
    override val data: ByteArray,
) : Key {
    init {
        require(data.size == 65) { "Invalid ec point length" }
        require(data[0] == 0x04.toByte()) { "Default data must be an uncompressed ec point" }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as EcPublicKey

        if (curve != other.curve) return false
        if (!data.contentEquals(other.data)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = curve.hashCode()
        result = 31 * result + data.contentHashCode()
        return result
    }

    companion object {
        const val oid: String = "1.2.840.10045.2.1"
    }
}

fun EcPublicKey.encodeToAsn1(): ByteArray =
    Asn1Encoder().write {
        writeTaggedObject(Asn1Type.Sequence.toConstructedTag()) {
            writeTaggedObject(Asn1Type.Sequence.toConstructedTag()) {
                writeObjectIdentifier(EcPublicKey.oid)
                writeObjectIdentifier(curve.oid)
            }
            writeBitString(this@encodeToAsn1.data)
        }
    }

fun EcPublicKey.encodeToPem(): String =
    Pem(type = "PUBLIC KEY", data = encodeToAsn1()).encodeToString()

/**
 * Returns an [EcPublicKey] from an uncompressed EC point representation.
 *
 * The expected format for the uncompressed point is:
 *
 * `[0x04] [32 bytes x-coordinate] [32 bytes y-coordinate]`
 */
fun EcPublicKey.Companion.fromUncompressedFormat(
    curve: EcCurve,
    data: ByteArray,
): EcPublicKey = EcPublicKey(curve, data)

/**
 * Parses a ASN.1 DER encoded subject public key info and returns an [EcPublicKey].
 *
 * The input should be the raw bytes of the EC public key encoded according to the following ASN.1 structure:
 *
 * SubjectPublicKeyInfo  ::=  SEQUENCE  {
 *   algorithm         AlgorithmIdentifier,
 *   subjectPublicKey  BIT STRING
 * }
 */
fun EcPublicKey.Companion.decodeFromAsn1(data: ByteArray): EcPublicKey =
    Asn1Decoder(data).read {
        advanceWithTag(Asn1Type.Sequence.toConstructedTag()) {
            val curve = readEcCurveFromAlgorithmIdentifier()
            val point = readBitString()
            skipToEnd()

            EcPublicKey.fromUncompressedFormat(curve, point)
        }
    }

/**
 * Parses a public key from a PEM-encoded string and returns an [EcPublicKey].
 */
fun EcPublicKey.Companion.decodeFromPem(data: String): EcPublicKey {
    val pem = data.decodeToPem()
    return EcPublicKey.decodeFromAsn1(pem.data)
}

@ExperimentalCryptoApi
class EcPrivateKey internal constructor(
    val curve: EcCurve,
    override val data: ByteArray,
) : Key {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as EcPrivateKey

        if (curve != other.curve) return false
        if (!data.contentEquals(other.data)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = curve.hashCode()
        result = 31 * result + data.contentHashCode()
        return result
    }

    companion object
}

fun EcPrivateKey.Companion.fromScalar(
    curve: EcCurve,
    data: ByteArray,
): EcPrivateKey = EcPrivateKey(curve, data)

fun EcPrivateKey.encodeToAsn1(): ByteArray =
    Asn1Encoder().write {
        writeTaggedObject(Asn1Type.Sequence.toConstructedTag()) {
            writeInt(0)
            writeTaggedObject(Asn1Type.Sequence.toConstructedTag()) {
                writeObjectIdentifier(EcPublicKey.oid)
                writeObjectIdentifier(curve.oid)
            }
            writeTaggedObject(Asn1Type.OctetString) {
                writeTaggedObject(Asn1Type.Sequence.toConstructedTag()) {
                    writeInt(1)
                    writeOctetString(this@encodeToAsn1.data)
                }
            }
        }
    }

fun EcPrivateKey.encodeToPem(): String =
    Pem(type = "EC PRIVATE KEY", data = encodeToAsn1()).encodeToString()

/**
 * Parses a ASN.1 DER encoded private key and returns an [EcPrivateKey].
 *
 * The input should be the raw bytes of the EC private key encoded according to the following ASN.1 structure:
 *
 * PrivateKeyInfo ::= SEQUENCE {
 *   version Version,
 *   privateKeyAlgorithm PrivateKeyAlgorithmIdentifier,
 *   privateKey PrivateKey,
 *   attributes [0] IMPLICIT Attributes OPTIONAL
 * }
 *
 * PrivateKeyAlgorithmIdentifier ::= AlgorithmIdentifier
 *
 * PrivateKey ::= OCTET STRING
 *
 * ECPrivateKey ::= SEQUENCE {
 *   version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
 *   privateKey     OCTET STRING,
 *   parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
 *   publicKey  [1] BIT STRING OPTIONAL
 * }
 */
fun EcPrivateKey.Companion.decodeFromAsn1(data: ByteArray): EcPrivateKey =
    Asn1Decoder(data).read {
        advanceWithTag(Asn1Type.Sequence.toConstructedTag()) {
            readInt()
            val curve = readEcCurveFromAlgorithmIdentifier()
            advanceWithTag(Asn1Type.OctetString) {
                advanceWithTag(Asn1Type.Sequence.toConstructedTag()) {
                    val version = readInt()
                    if (version != 1) fail { "Unsupported ec private key version" }
                    val privateKey = readOctetString()
                    skipToEnd()

                    EcPrivateKey(curve, privateKey)
                }
            }
        }
    }

/**
 * Parses a private key from a PEM-encoded string and returns an [EcPrivateKey].
 */
fun EcPrivateKey.Companion.decodeFromPem(data: String): EcPrivateKey {
    val pem = data.decodeToPem()
    return EcPrivateKey.decodeFromAsn1(pem.data)
}

/**
 * Parses a ASN.1 DER encoded algorithm identifier and returns an [EcPublicKey].
 *
 * AlgorithmIdentifier  ::=  SEQUENCE  {
 *   algorithm   OBJECT IDENTIFIER,
 *   parameters  ANY DEFINED BY algorithm OPTIONAL
 * }
 */
fun Asn1Decoder.ParserScope.readEcCurveFromAlgorithmIdentifier(): EcCurve =
    advanceWithTag(Asn1Type.Sequence.toConstructedTag()) {
        val oid = readObjectIdentifier()
        require(oid == EcPublicKey.oid) { "Unexpected oid `$oid`. Expected `${EcPublicKey.oid}`" }
        val curveOid = readObjectIdentifier()
        skipToEnd()

        EcCurve.entries.find { it.oid == curveOid } ?: fail { "Unknown curve with oid `$curveOid`" }
    }