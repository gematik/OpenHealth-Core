/*
 * Copyright 2025 gematik GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

@file:Suppress("MagicNumber")

package de.gematik.openhealth.smartcard.identifier

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

    /**
     * Returns the file identifier as a byte array.
     */
    fun getFid(): ByteArray = byteArrayOf((fid shr 8).toByte(), fid.toByte())

    @OptIn(ExperimentalStdlibApi::class)
    private fun sanityCheck() {
        // gemSpec_COS_3.14.0#N006.700, N006.900
        require(!((fid < 0x1000 || fid > 0xFEFF) && fid != 0x011C || fid == 0x3FFF)) {
            "File Identifier is out of range: 0x" + getFid().toHexString()
        }
    }
}
