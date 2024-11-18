

package de.gematik.ti.healthcard.model.exchange

import de.gematik.ti.healthcard.model.CardUtilities

private const val PARAMETER256 = 13
private const val PARAMETER384 = 16
private const val PARAMETER512 = 17

/**
 * Extracts PACE Information from CardAccess
 */
class PaceInfo(
    cardAccess: ByteArray,
) {
    private val protocol: ASN1ObjectIdentifier
    private val parameterID: Int

    /**
     * Returns PACE info protocol bytes
     */
    val paceInfoProtocolBytes: ByteArray =
        ASN1InputStream(cardAccess).use { asn1InputStream ->
            val app = asn1InputStream.readObject() as DLSet
            val seq = app.getObjectAt(0) as ASN1Sequence
            protocol = seq.getObjectAt(0) as ASN1ObjectIdentifier
            parameterID = (seq.getObjectAt(2) as ASN1Integer).value.toInt()

            protocol.encoded.let {
                it.copyOfRange(2, it.size)
            }
        }

    /**
     * PACE info protocol ID
     */
    val protocolID: String = protocol.id

    private val ecNamedCurveParameterSpec =
        ECNamedCurveTable.getParameterSpec(
            when (parameterID) {
                PARAMETER256 -> "BrainpoolP256r1"
                PARAMETER384 -> "BrainpoolP384r1"
                PARAMETER512 -> "BrainpoolP512r1"
                else -> ""
            },
        )

    val ecCurve = ecNamedCurveParameterSpec.curve
    val ecPointG = ecNamedCurveParameterSpec.g

    fun convertECPoint(ecPoint: ByteArray) = CardUtilities.byteArrayToECPoint(ecPoint, ecCurve)
}