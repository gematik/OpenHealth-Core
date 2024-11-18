@file:Suppress("MagicNumber")

package de.gematik.ti.healthcard.model.identifier

/**
 * A file identifier may reference any file. It consists of two bytes. The value '3F00'
 * is reserved for referencing the MF. The value 'FFFF' is reserved for future use. The value '3FFF' is reserved
 * (see below and 7.4.1). The value '0000' is reserved (see 7.2.2 and 7.4.1). In order to unambiguously select
 * any file by its identifier, all EFs and DFs immediately under a given DF shall have different file identifiers.
 * @see "ISO/IEC 7816-4"
 */
class FileIdentifier {
    private val fid: Int

    constructor(fid: ByteArray) {
        require(fid.size == 2) {
            "requested length of byte array for a File Identifier value is 2 but was " +
                fid.size
        }
        this.fid = (fid[0].toInt() and 0xFF shl 8) or (fid[1].toInt() and 0xFF)
        sanityCheck()
    }

    constructor(fid: Int) {
        this.fid = fid
        sanityCheck()
    }

    @OptIn(ExperimentalStdlibApi::class)
    constructor(hexFid: String) : this(hexFid.hexToByteArray())

    fun getFid(): ByteArray = byteArrayOf((fid shr 8).toByte(), fid.toByte())

    @OptIn(ExperimentalStdlibApi::class)
    private fun sanityCheck() {
        // gemSpec_COS#N006.700, N006.900
        require(!((fid < 0x1000 || fid > 0xFEFF) && fid != 0x011C || fid == 0x3FFF)) {
            "File Identifier is out of range: 0x" + getFid().toHexString()
        }
    }
}