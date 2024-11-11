/*
 * ${GEMATIK_COPYRIGHT_STATEMENT}
 */

package de.gematik.ti.healthcard.model

import de.gematik.ti.healthcard.BCProvider
import org.bouncycastle.asn1.ASN1InputStream
import org.bouncycastle.asn1.ASN1Object
import org.bouncycastle.asn1.ASN1TaggedObject
import org.bouncycastle.math.ec.ECCurve
import org.bouncycastle.math.ec.ECPoint

/**
 * Utility class for card functions
 */
object CardUtilities {
    private const val UNCOMPRESSEDPOINTVALUE = 0x04

    /**
     * Decodes an ECPoint from byte array. Prime field p is taken from the passed curve
     * The first byte must contain the value 0x04 (uncompressed point).
     *
     * @param byteArray Byte array of the form {0x04 || x-bytes [] || y byte []}
     * @param curve     The curve on which the point should lie.
     * @return EC point generated from input data
     */
    fun byteArrayToECPoint(byteArray: ByteArray, curve: ECCurve): ECPoint {
        return if (byteArray[0] != UNCOMPRESSEDPOINTVALUE.toByte()) {
            throw IllegalArgumentException("Found no uncompressed point!")
        } else {
            val x = ByteArray((byteArray.size - 1) / 2)
            val y = ByteArray((byteArray.size - 1) / 2)

            System.arraycopy(byteArray, 1, x, 0, (byteArray.size - 1) / 2)
            System.arraycopy(
                byteArray,
                1 + (byteArray.size - 1) / 2,
                y,
                0,
                (byteArray.size - 1) / 2
            )
            curve.createPoint(BigInteger(1, x), BigInteger(1, y))
        }
    }

    /**
     * Encodes an ASN1 KeyObject
     */
    fun extractKeyObjectEncoded(asn1Input: ByteArray): ByteArray =
        ASN1InputStream(asn1Input).use { asn1InputStream ->
            val seq = asn1InputStream.readObject() as ASN1TaggedObject
            val seqObj: ASN1Object = seq.baseObject
            seqObj.encoded.copyOfRange(2, seqObj.encoded.size)
        }
}

fun ByteArray.toX509Certificate() =
    CertificateFactory.getInstance("X.509", BCProvider).let {
        it.generateCertificate(this.inputStream()) as X509Certificate
    }
