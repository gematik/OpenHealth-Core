/*
 * ${GEMATIK_COPYRIGHT_STATEMENT}
 */

package de.gematik.ti.healthcard.model.nfc.tagobjects

import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.DERTaggedObject

private const val DO_87_TAG = 0x07
private const val DO_81_EXTRACTED_TAG = 0x81
private const val DO_81_TAG = 0x01

/**
 * Data object with TAG 87
 *
 * @param data byte array with extracted data from plain CommandApdu or encrypted ResponseApdu
 * @param tag int with extracted tag number
 */
class DataObject(val data: ByteArray, val tag: Byte = 0) {
    val taggedObject: DERTaggedObject
        get() =
            if (tag == DO_81_EXTRACTED_TAG.toByte()) {
                DERTaggedObject(false, DO_81_TAG, DEROctetString(data))
            } else {
                DERTaggedObject(false, DO_87_TAG, DEROctetString(data))
            }
}
