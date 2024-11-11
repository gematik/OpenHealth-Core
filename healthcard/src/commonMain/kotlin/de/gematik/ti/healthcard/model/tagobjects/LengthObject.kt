/*
 * ${GEMATIK_COPYRIGHT_STATEMENT}
 */

package de.gematik.ti.healthcard.model.nfc.tagobjects

import de.gematik.ti.healthcard.model.command.EXPECTED_LENGTH_WILDCARD_SHORT
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.DERTaggedObject

private const val DO_97_TAG = 0x17
private const val BYTE_MASK = 0xFF
private const val BYTE_VALUE = 8

/**
 * Length object with TAG 97
 *
 * @param le extracted expected length from plain CommandApdu
 */
class LengthObject(le: Int) {
    private var leData = ByteArray(0)
    val taggedObject: DERTaggedObject
        get() = DERTaggedObject(false, DO_97_TAG, DEROctetString(leData))

    init {
        if (le >= 0) {
            leData = when {
                le == EXPECTED_LENGTH_WILDCARD_SHORT -> {
                    byteArrayOf(0x00)
                }
                le > EXPECTED_LENGTH_WILDCARD_SHORT -> {
                    byteArrayOf(
                        (le shr BYTE_VALUE and BYTE_MASK).toByte(),
                        (le and BYTE_MASK).toByte()
                    )
                }
                else -> {
                    byteArrayOf(le.toByte())
                }
            }
        }
    }
}
