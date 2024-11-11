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

package de.gematik.openhealth.crypto.key

import com.ionspin.kotlin.bignum.integer.BigInteger
import com.ionspin.kotlin.bignum.integer.Sign
import de.gematik.openhealth.asn1.Asn1Decoder
import de.gematik.openhealth.asn1.Asn1Encoder
import de.gematik.openhealth.asn1.Asn1Tag
import de.gematik.openhealth.asn1.Asn1Type
import de.gematik.openhealth.asn1.readBitString
import de.gematik.openhealth.asn1.readInt
import de.gematik.openhealth.asn1.readObjectIdentifier
import de.gematik.openhealth.asn1.readOctetString
import de.gematik.openhealth.asn1.writeBitString
import de.gematik.openhealth.asn1.writeInt
import de.gematik.openhealth.asn1.writeObjectIdentifier
import de.gematik.openhealth.asn1.writeOctetString
import de.gematik.openhealth.asn1.writeTaggedObject
import de.gematik.openhealth.crypto.ExperimentalCryptoApi
import de.gematik.openhealth.crypto.Pem
import de.gematik.openhealth.crypto.decodeToPem
import de.gematik.openhealth.crypto.encodeToString

/**
 * Elliptic curve parameters according to RFC 5639.
 */
@ExperimentalCryptoApi
@Suppress("detekt.MaxLineLength")
enum class EcCurve(
    val oid: String,
) {
    BrainpoolP256r1("1.3.36.3.3.2.8.1.1.7") {
        override val p: BigInteger
            get() =
                BigInteger.parseString(
                    "A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377",
                    base = 16,
                )
        override val a: BigInteger
            get() =
                BigInteger.parseString(
                    "7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9",
                    base = 16,
                )
        override val b: BigInteger
            get() =
                BigInteger.parseString(
                    "26DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B6",
                    base = 16,
                )
        override val x: BigInteger
            get() =
                BigInteger.parseString(
                    "8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262",
                    base = 16,
                )
        override val y: BigInteger
            get() =
                BigInteger.parseString(
                    "547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997",
                    base = 16,
                )
        override val q: BigInteger
            get() =
                BigInteger.parseString(
                    "A9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7",
                    base = 16,
                )
    },
    BrainpoolP384r1("1.3.36.3.3.2.8.1.1.11") {
        override val p: BigInteger
            get() =
                BigInteger.parseString(
                    "8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B412B1DA197FB71123ACD3A729901D1A71874700133107EC53",
                    base = 16,
                )
        override val a: BigInteger
            get() =
                BigInteger.parseString(
                    "7BC382C63D8C150C3C72080ACE05AFA0C2BEA28E4FB22787139165EFBA91F90F8AA5814A503AD4EB04A8C7DD22CE2826",
                    base = 16,
                )
        override val b: BigInteger
            get() =
                BigInteger.parseString(
                    "04A8C7DD22CE28268B39B55416F0447C2FB77DE107DCD2A62E880EA53EEB62D57CB4390295DBC9943AB78696FA504C11",
                    base = 16,
                )
        override val x: BigInteger
            get() =
                BigInteger.parseString(
                    "1D1C64F068CF45FFA2A63A81B7C13F6B8847A3E77EF14FE3DB7FCAFE0CBD10E8E826E03436D646AAEF87B2E247D4AF1E",
                    base = 16,
                )
        override val y: BigInteger
            get() =
                BigInteger.parseString(
                    "8ABE1D7520F9C2A45CB1EB8E95CFD55262B70B29FEEC5864E19C054FF99129280E4646217791811142820341263C5315",
                    base = 16,
                )
        override val q: BigInteger
            get() =
                BigInteger.parseString(
                    "8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B31F166E6CAC0425A7CF3AB6AF6B7FC3103B883202E9046565",
                    base = 16,
                )
    },
    BrainpoolP512r1("1.3.36.3.3.2.8.1.1.13") {
        override val p: BigInteger
            get() =
                BigInteger.parseString(
                    "AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA703308717D4D9B009BC66842AECDA12AE6A380E62881FF2F2D82C68528AA6056583A48F3",
                    base = 16,
                )
        override val a: BigInteger
            get() =
                BigInteger.parseString(
                    "7830A3318B603B89E2327145AC234CC594CBDD8D3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CA",
                    base = 16,
                )
        override val b: BigInteger
            get() =
                BigInteger.parseString(
                    "3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CADC083E67984050B75EBAE5DD2809BD638016F723",
                    base = 16,
                )
        override val x: BigInteger
            get() =
                BigInteger.parseString(
                    "81AEE4BDD82ED9645A21322E9C4C6A9385ED9F70B5D916C1B43B62EEF4D0098EFF3B1F78E2D0D48D50D1687B93B97D5F7C6D5047406A5E688B352209BCB9F822",
                    base = 16,
                )
        override val y: BigInteger
            get() =
                BigInteger.parseString(
                    "7DDE385D566332ECC0EABFA9CF7822FDF209F70024A57B1AA000C55B881F8111B2DCDE494A5F485E5BCA4BD88A2763AED1CA2B2FA8F0540678CD1E0F3AD80892",
                    base = 16,
                )
        override val q: BigInteger
            get() =
                BigInteger.parseString(
                    "AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA70330870553E5C414CA92619418661197FAC10471DB1D381085DDADDB58796829CA90069",
                    base = 16,
                )
    }, ;

    abstract val p: BigInteger
    abstract val a: BigInteger
    abstract val b: BigInteger
    abstract val x: BigInteger
    abstract val y: BigInteger
    abstract val q: BigInteger

    val g: EcPoint get() = EcPoint(this, x, y)

    fun point(
        x: BigInteger?,
        y: BigInteger?,
    ): EcPoint = EcPoint(this, x, y)
}

/**
 * Specification for EC key pair generation.
 */
class EcKeyPairSpec(
    val curve: EcCurve,
)

/**
 * Generates a new EC key pair.
 */
expect fun EcKeyPairSpec.generateKeyPair(): Pair<EcPublicKey, EcPrivateKey>

// @ExperimentalCryptoApi
// expect  fun EcCurve.generateKeyPair(): EcPublicKey
//
// @ExperimentalCryptoApi
// expect  fun EcCurve.generateKeyPair(): Pair<EcPublicKey, EcPrivateKey>

/**
 * EC public key implementation with curve parameters and uncompressed point data.
 */
@ExperimentalCryptoApi
class EcPublicKey internal constructor(
    val curve: EcCurve,
    override val data: ByteArray,
) : Key {
    init {
        val requiredEcPointLength =
            when (curve) {
                EcCurve.BrainpoolP256r1 -> 65
                EcCurve.BrainpoolP384r1 -> 97
                EcCurve.BrainpoolP512r1 -> 129
            }
        require(data.size == requiredEcPointLength) { "Invalid ec point length `${data.size}`" }
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

    override fun toString(): String = "EcPublicKey(data=${data.contentToString()}, curve=$curve)"

    companion object {
        const val OID: String = "1.2.840.10045.2.1"
    }
}

/**
 * Elliptic curve point representation.
 */
fun EcPublicKey.toEcPoint(): EcPoint {
    val coordinateSize =
        when (curve) {
            EcCurve.BrainpoolP256r1 -> 32
            EcCurve.BrainpoolP384r1 -> 48
            EcCurve.BrainpoolP512r1 -> 64
        }
    return EcPoint(
        curve,
        BigInteger.fromByteArray(data.sliceArray(1..coordinateSize), Sign.POSITIVE),
        BigInteger.fromByteArray(
            data.sliceArray((coordinateSize + 1)..(2 * coordinateSize)),
            Sign.POSITIVE,
        ),
    )
}

/**
 * Encodes the public key as an ASN.1 DER encoded subject public key info.
 *
 * The output will be the raw bytes of the EC public key encoded according to the following ASN.1 structure:
 *
 * SubjectPublicKeyInfo  ::=  SEQUENCE  {
 *   algorithm         AlgorithmIdentifier,
 *   subjectPublicKey  BIT STRING
 * }
 */
fun EcPublicKey.encodeToAsn1(): ByteArray =
    Asn1Encoder().write {
        writeTaggedObject(Asn1Type.SEQUENCE, Asn1Tag.CONSTRUCTED) {
            writeTaggedObject(Asn1Type.SEQUENCE, Asn1Tag.CONSTRUCTED) {
                writeObjectIdentifier(EcPublicKey.OID)
                writeObjectIdentifier(curve.oid)
            }
            writeBitString(this@encodeToAsn1.data)
        }
    }

/**
 * Encodes the public key as a PEM-encoded string.
 */
fun EcPublicKey.encodeToPem(): String =
    Pem(type = "PUBLIC KEY", data = encodeToAsn1()).encodeToString()

/**
 * Returns an [EcPublicKey] from an uncompressed EC point representation.
 *
 * The expected format for the uncompressed point is:
 *
 * `[0x04] [32 bytes x-coordinate] [32 bytes y-coordinate]`
 */
fun EcPublicKey.Companion.decodeFromUncompressedFormat(
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
        advanceWithTag(Asn1Type.SEQUENCE, Asn1Tag.CONSTRUCTED) {
            val curve = readEcCurveFromAlgorithmIdentifier()
            val point = readBitString()
            skipToEnd()

            EcPublicKey.decodeFromUncompressedFormat(curve, point)
        }
    }

/**
 * Parses a public key from a PEM-encoded string and returns an [EcPublicKey].
 */
fun EcPublicKey.Companion.decodeFromPem(data: String): EcPublicKey {
    val pem = data.decodeToPem()
    return EcPublicKey.decodeFromAsn1(pem.data)
}

/**
 * Elliptic curve private key implementation with curve parameters and scalar data.
 */
@ExperimentalCryptoApi
class EcPrivateKey internal constructor(
    val curve: EcCurve,
    override val data: ByteArray,
) : Key {
    val s: BigInteger = BigInteger.fromByteArray(data, Sign.POSITIVE)

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

    override fun toString(): String = "EcPrivateKey(data=${data.contentToString()}, curve=$curve)"

    companion object
}

/**
 * Creates an [EcPrivateKey] from a scalar value.
 */
fun EcPrivateKey.Companion.fromScalar(
    curve: EcCurve,
    data: ByteArray,
): EcPrivateKey = EcPrivateKey(curve, data)

/**
 * Encodes the private key as an ASN.1 DER encoded private key info.
 *
 * The output will be the raw bytes of the EC private key encoded
 * according to the following ASN.1 structure:
 *
 * PrivateKeyInfo ::= SEQUENCE {
 *   version Version,
 *   privateKeyAlgorithm PrivateKeyAlgorithmIdentifier,
 *   privateKey PrivateKey,
 *   attributes [0] IMPLICIT Attributes OPTIONAL
 * }
 */
fun EcPrivateKey.encodeToAsn1(): ByteArray =
    Asn1Encoder().write {
        writeTaggedObject(Asn1Type.SEQUENCE, Asn1Tag.CONSTRUCTED) {
            writeInt(0)
            writeTaggedObject(Asn1Type.SEQUENCE, Asn1Tag.CONSTRUCTED) {
                writeObjectIdentifier(EcPublicKey.OID)
                writeObjectIdentifier(curve.oid)
            }
            writeTaggedObject(Asn1Type.OCTET_STRING) {
                writeTaggedObject(Asn1Type.SEQUENCE, Asn1Tag.CONSTRUCTED) {
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
        advanceWithTag(Asn1Type.SEQUENCE, Asn1Tag.CONSTRUCTED) {
            readInt()
            val curve = readEcCurveFromAlgorithmIdentifier()
            advanceWithTag(Asn1Type.OCTET_STRING) {
                advanceWithTag(Asn1Type.SEQUENCE, Asn1Tag.CONSTRUCTED) {
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
 * Parses an ASN.1 DER encoded algorithm identifier and returns an [EcPublicKey].
 *
 * AlgorithmIdentifier  ::=  SEQUENCE  {
 *   algorithm   OBJECT IDENTIFIER,
 *   parameters  ANY DEFINED BY algorithm OPTIONAL
 * }
 */
fun Asn1Decoder.ParserScope.readEcCurveFromAlgorithmIdentifier(): EcCurve =
    advanceWithTag(Asn1Type.SEQUENCE, Asn1Tag.CONSTRUCTED) {
        val oid = readObjectIdentifier()
        require(oid == EcPublicKey.OID) { "Unexpected oid `$oid`. Expected `${EcPublicKey.OID}`" }
        val curveOid = readObjectIdentifier()
        skipToEnd()

        EcCurve.entries.find { it.oid == curveOid } ?: fail { "Unknown curve with oid `$curveOid`" }
    }
