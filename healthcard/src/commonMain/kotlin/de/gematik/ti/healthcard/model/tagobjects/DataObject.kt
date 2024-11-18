

package de.gematik.ti.healthcard.model.tagobjects

import de.gematik.kmp.asn1.Asn1Encoder
import de.gematik.kmp.asn1.writeTaggedObject

private const val DO_87_TAG = 0x07
private const val DO_81_EXTRACTED_TAG = 0x81
private const val DO_81_TAG = 0x01

/**
 * Data object with TAG 87
 *
 * @param data byte array with extracted data from plain CommandApdu or encrypted ResponseApdu
 * @param tag int with extracted tag number
 */
class DataObject(
    val data: ByteArray,
    val tag: Byte = 0,
) {
    val encoded: ByteArray
        get() {
            val encoder = Asn1Encoder()
            return encoder.write {
                val actualTag = if (tag == DO_81_EXTRACTED_TAG.toByte()) DO_81_TAG else DO_87_TAG
                writeTaggedObject(actualTag) {
                    write(data) // Write the raw data as an octet string
                }
            }
        }
}