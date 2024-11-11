/*
 * ${GEMATIK_COPYRIGHT_STATEMENT}
 */

package de.gematik.ti.healthcard.model.nfc.tagobjects

import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.DERTaggedObject

private const val DO_99_TAG = 0x19

/**
 * Status object with TAG 99
 *
 * @param statusBytes byte array with extracted response status from encrypted ResponseApdu
 */
class StatusObject(private val statusBytes: ByteArray) {
    val taggedObject: DERTaggedObject =
        DERTaggedObject(false, DO_99_TAG, DEROctetString(statusBytes))
}
