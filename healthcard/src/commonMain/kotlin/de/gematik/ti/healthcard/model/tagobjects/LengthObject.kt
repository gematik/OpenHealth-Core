/*
 * ${GEMATIK_COPYRIGHT_STATEMENT}
 */

package de.gematik.ti.healthcard.model.tagobjects

import de.gematik.kmp.asn1.Asn1Encoder
import de.gematik.kmp.asn1.writeTaggedObject
import de.gematik.ti.healthcard.model.command.EXPECTED_LENGTH_WILDCARD_SHORT

private const val DO_97_TAG = 0x17
private const val BYTE_MASK = 0xFF
private const val BYTE_VALUE = 8

/**
 * Length object with TAG 97
 *
 * @param le extracted expected length from plain CommandApdu
 */
class LengthObject(le: Int) {
    private val leData: ByteArray

    init {
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

    val encoded: ByteArray
        get() {
            val encoder = Asn1Encoder()
            return encoder.write {
                writeTaggedObject(DO_97_TAG) {
                    write(leData) // Write the length data as an octet string
                }
            }
        }
}
