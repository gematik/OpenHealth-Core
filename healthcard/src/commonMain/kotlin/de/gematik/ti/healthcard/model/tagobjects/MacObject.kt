/*
 * ${GEMATIK_COPYRIGHT_STATEMENT}
 */

package de.gematik.ti.healthcard.model.tagobjects

import de.gematik.kmp.asn1.Asn1Encoder
import de.gematik.kmp.asn1.writeTaggedObject
import de.gematik.ti.healthcard.utils.Bytes.padData

private const val DO_8E_TAG = 0x0E
private const val MAC_SIZE = 8
private const val BLOCK_SIZE = 16

/**
 * Mac object with TAG 8E (cryptographic checksum)
 *
 *
 * @param header byte array with extracted header from plain CommandApdu
 * @param commandDataOutput ByteArrayOutputStream with extracted data and expected length from plain CommandApdu
 * @param kMac byte array with Session key for message authentication
 * @param ssc byte array with send sequence counter
 */
class MacObject(
    private val header: ByteArray? = null,
    private val commandOutput: ByteArray,
    private val kMac: ByteArray,
    private val ssc: ByteArray
) {
    private val mac: ByteArray

    init {
        mac = calculateMac()
    }

    val encoded: ByteArray
        get() {
            val encoder = Asn1Encoder()
            return encoder.write {
                writeTaggedObject(DO_8E_TAG) {
                    write(mac) // Write the calculated MAC as an octet string
                }
            }
        }

    private fun calculateMac(): ByteArray {
        val cbcMac = getCMac(ssc, kMac)

        if (header != null) {
            val paddedHeader = padData(header, BLOCK_SIZE)
            cbcMac.update(paddedHeader, 0, paddedHeader.size)
        }
        if (commandOutput.isNotEmpty()) {
            val paddedData = padData(commandOutput, BLOCK_SIZE)
            cbcMac.update(paddedData, 0, paddedData.size)
        }

        val macData = ByteArray(BLOCK_SIZE)
        cbcMac.doFinal(macData, 0)

        return macData.copyOfRange(0, MAC_SIZE)
    }

    private fun getCMac(secureMessagingSSC: ByteArray, kMac: ByteArray): CMac =
        CMac(AESEngine()).apply {
            init(KeyParameter(kMac))
            update(secureMessagingSSC, 0, secureMessagingSSC.size)
        }
}
