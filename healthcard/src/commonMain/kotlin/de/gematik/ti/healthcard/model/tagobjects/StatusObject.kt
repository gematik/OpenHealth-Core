

package de.gematik.ti.healthcard.model.tagobjects

import de.gematik.kmp.asn1.Asn1Encoder
import de.gematik.kmp.asn1.writeTaggedObject

private const val DO_99_TAG = 0x19

/**
 * Status object with TAG 99
 *
 * @param statusBytes byte array with extracted response status from encrypted ResponseApdu
 */
class StatusObject(
    private val statusBytes: ByteArray,
) {
    val encoded: ByteArray
        get() {
            val encoder = Asn1Encoder()
            return encoder.write {
                writeTaggedObject(DO_99_TAG) {
                    write(statusBytes) // Write the status bytes as an octet string
                }
            }
        }
}